package com.hephaistos.hsigner.engine

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Inspecteur binaire bas niveau des blocs de signature APK :
 * - Blocs APK Signing Block ("APK Sig Block 42") : V2 (0x7109871a), V3 (0xf05368c0),
 *   V3.1 (0x1b93ad61), SourceStamp V1/V2 (0x2b09189e / 0x6dff800d).
 * - Entrées JAR V1 (META-INF .RSA, .DSA, .EC) avec extraction des octets PKCS#7 bruts.
 * - Fichier compagnon V4 (.idsig) avec lecture de l'en-tête binaire.
 */
object ApkSigningBlockInspector {

    const val ID_V2_BLOCK = 0x7109871a
    const val ID_V3_BLOCK = 0xf05368c0.toInt()
    const val ID_V31_BLOCK = 0x1b93ad61
    const val ID_SOURCE_STAMP_V1 = 0x2b09189e
    const val ID_SOURCE_STAMP_V2 = 0x6dff800d
    const val ID_DEPENDENCY_INFO = 0x504b4453

    private val APK_SIG_BLOCK_MAGIC = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)
    private const val ZIP_EOCD_SIG = 0x06054b50

    data class DetectedBlocks(
        val hasV1JarEntries: Boolean,
        val v1SignatureEntryNames: List<String>,
        val v1RawPkcs7SignatureBytes: ByteArray?,
        val hasV2Block: Boolean,
        val hasV3Block: Boolean,
        val hasV31Block: Boolean,
        val hasSourceStampBlock: Boolean,
        val blockIdsHex: List<String>,
        val signingBlockSizeBytes: Long?
    )

    data class V4IdsigSummary(
        val version: Int,
        val hashingAlgorithm: Int,
        val log2BlockSize: Int,
        val apkDigestHex: String,
        val signingCertificateBytes: ByteArray?,
        val rawSignatureBytes: ByteArray?
    )

    fun inspect(apkFile: File): DetectedBlocks {
        val v1Names = mutableListOf<String>()
        var firstPkcs7Bytes: ByteArray? = null

        runCatching {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val upper = entry.name.uppercase()
                    if (upper.startsWith("META-INF/") &&
                        !upper.substringAfter("META-INF/").contains('/') &&
                        (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC"))
                    ) {
                        v1Names.add(entry.name)
                        if (firstPkcs7Bytes == null) {
                            firstPkcs7Bytes = zip.getInputStream(entry).use { it.readBytes() }
                        }
                    }
                }
            }
        }

        val blockIds = mutableListOf<Int>()
        var blockSize: Long? = null

        runCatching {
            RandomAccessFile(apkFile, "r").use { raf ->
                val fileLength = raf.length()
                val eocdOffset = findZipEocdOffset(raf, fileLength) ?: return@use
                val cdOffset = readUint32LE(raf, eocdOffset + 16)
                if (cdOffset < 32 || cdOffset > eocdOffset) return@use

                // Pied du bloc APK Signing Block juste avant Central Directory (24 octets : size64 + 16B magic)
                val footerOffset = cdOffset - 24
                val magic = ByteArray(16)
                raf.seek(footerOffset + 8)
                raf.readFully(magic)
                if (!magic.contentEquals(APK_SIG_BLOCK_MAGIC)) return@use

                val sizeInFooter = readUint64LE(raf, footerOffset)
                if (sizeInFooter < 24 || sizeInFooter > cdOffset) return@use
                val blockStart = cdOffset - sizeInFooter - 8
                if (blockStart < 0) return@use
                val sizeInHeader = readUint64LE(raf, blockStart)
                if (sizeInHeader != sizeInFooter) return@use

                blockSize = sizeInFooter + 8
                var pos = blockStart + 8
                val pairsEnd = cdOffset - 24
                while (pos + 12 <= pairsEnd) {
                    val pairLen = readUint64LE(raf, pos)
                    if (pairLen < 4 || pos + 8 + pairLen > pairsEnd) break
                    val id = readInt32LE(raf, pos + 8)
                    blockIds.add(id)
                    pos += 8 + pairLen
                }
            }
        }

        return DetectedBlocks(
            hasV1JarEntries = v1Names.isNotEmpty(),
            v1SignatureEntryNames = v1Names,
            v1RawPkcs7SignatureBytes = firstPkcs7Bytes,
            hasV2Block = blockIds.contains(ID_V2_BLOCK),
            hasV3Block = blockIds.contains(ID_V3_BLOCK),
            hasV31Block = blockIds.contains(ID_V31_BLOCK),
            hasSourceStampBlock = blockIds.contains(ID_SOURCE_STAMP_V1) || blockIds.contains(ID_SOURCE_STAMP_V2),
            blockIdsHex = blockIds.map { "0x" + Integer.toHexString(it) },
            signingBlockSizeBytes = blockSize
        )
    }

    /**
     * Parse l'en-tête binaire officiel d'un fichier .idsig (APK Signature Scheme v4).
     */
    fun inspectIdsig(idsigFile: File): V4IdsigSummary? {
        if (!idsigFile.exists() || idsigFile.length() < 16) return null
        return runCatching {
            val bytes = idsigFile.readBytes()
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val version = buf.getInt()
            if (version != 2 && version != 4) return null

            // HashingInfo (length-prefixed)
            val hashInfoLen = buf.getInt()
            if (hashInfoLen < 6 || buf.remaining() < hashInfoLen) return null
            val hashStart = buf.position()
            val hashAlg = buf.getInt()
            val log2BlockSize = buf.get().toInt() and 0xFF
            val saltLen = buf.getInt()
            if (saltLen < 0 || buf.remaining() < saltLen + 4) return null
            buf.position(buf.position() + saltLen)
            val rawRootHashLen = buf.getInt()
            if (rawRootHashLen < 0 || buf.position() + rawRootHashLen > hashStart + hashInfoLen) return null
            buf.position(hashStart + hashInfoLen)

            // SigningInfo (length-prefixed)
            if (buf.remaining() < 4) return null
            val signInfoLen = buf.getInt()
            if (signInfoLen < 12 || buf.remaining() < signInfoLen) return null
            val apkDigestLen = buf.getInt()
            val apkDigest = ByteArray(apkDigestLen.coerceIn(0, buf.remaining()))
            buf.get(apkDigest)

            val certLen = if (buf.remaining() >= 4) buf.getInt() else 0
            val certBytes = if (certLen > 0 && buf.remaining() >= certLen) {
                ByteArray(certLen).also { buf.get(it) }
            } else null

            // Skip additionalData + publicKey + signatureAlgorithm + read signature
            var sigBytes: ByteArray? = null
            if (buf.remaining() >= 4) {
                val addLen = buf.getInt()
                if (addLen >= 0 && buf.remaining() >= addLen) buf.position(buf.position() + addLen)
            }
            if (buf.remaining() >= 4) {
                val pkLen = buf.getInt()
                if (pkLen >= 0 && buf.remaining() >= pkLen) buf.position(buf.position() + pkLen)
            }
            if (buf.remaining() >= 8) {
                buf.getInt() // signatureAlgorithmId
                val sigLen = buf.getInt()
                if (sigLen > 0 && buf.remaining() >= sigLen) {
                    sigBytes = ByteArray(sigLen).also { buf.get(it) }
                }
            }

            V4IdsigSummary(
                version = version,
                hashingAlgorithm = hashAlg,
                log2BlockSize = log2BlockSize,
                apkDigestHex = apkDigest.joinToString("") { "%02x".format(it) },
                signingCertificateBytes = certBytes,
                rawSignatureBytes = sigBytes
            )
        }.getOrNull()
    }

    private fun findZipEocdOffset(raf: RandomAccessFile, fileLength: Long): Long? {
        if (fileLength < 22) return null
        val maxSearch = minOf(fileLength, 22L + 65535L).toInt()
        val buf = ByteArray(maxSearch)
        val start = fileLength - maxSearch
        raf.seek(start)
        raf.readFully(buf)

        for (i in maxSearch - 22 downTo 0) {
            if ((buf[i].toInt() and 0xFF) == 0x50 &&
                (buf[i + 1].toInt() and 0xFF) == 0x4B &&
                (buf[i + 2].toInt() and 0xFF) == 0x05 &&
                (buf[i + 3].toInt() and 0xFF) == 0x06
            ) {
                val commentLen = (buf[i + 20].toInt() and 0xFF) or ((buf[i + 21].toInt() and 0xFF) shl 8)
                if (i + 22 + commentLen == maxSearch) {
                    return start + i
                }
            }
        }
        return null
    }

    private fun readInt32LE(raf: RandomAccessFile, offset: Long): Int {
        raf.seek(offset)
        val b = ByteArray(4)
        raf.readFully(b)
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt()
    }

    private fun readUint32LE(raf: RandomAccessFile, offset: Long): Long {
        return readInt32LE(raf, offset).toLong() and 0xFFFFFFFFL
    }

    private fun readUint64LE(raf: RandomAccessFile, offset: Long): Long {
        raf.seek(offset)
        val b = ByteArray(8)
        raf.readFully(b)
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getLong()
    }
}
