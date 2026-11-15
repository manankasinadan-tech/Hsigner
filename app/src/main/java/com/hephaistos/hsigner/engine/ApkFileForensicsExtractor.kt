package com.hephaistos.hsigner.engine

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.ZipFile

/**
 * Calcule en flux (faible empreinte mémoire) les empreintes cryptographiques complètes
 * du fichier .apk entier (CRC32, MD5, SHA-1, SHA-256, SHA-512) et analyse sa structure ZIP
 * (classes.dex, bibliothèques natives par ABI, resources.arsc, métadonnées Kotlin).
 */
object ApkFileForensicsExtractor {

    fun extract(apkFile: File): ApkFileForensics {
        val crc = CRC32()
        val md5 = MessageDigest.getInstance("MD5")
        val sha1 = MessageDigest.getInstance("SHA-1")
        val sha256 = MessageDigest.getInstance("SHA-256")
        val sha512 = MessageDigest.getInstance("SHA-512")

        val buffer = ByteArray(64 * 1024)
        FileInputStream(apkFile).use { fis ->
            while (true) {
                val read = fis.read(buffer)
                if (read <= 0) break
                crc.update(buffer, 0, read)
                md5.update(buffer, 0, read)
                sha1.update(buffer, 0, read)
                sha256.update(buffer, 0, read)
                sha512.update(buffer, 0, read)
            }
        }

        var totalEntries = 0
        var dexCount = 0
        var nativeLibsCount = 0
        val abis = linkedSetOf<String>()
        var hasResourcesArsc = false
        var hasKotlinMeta = false

        runCatching {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    totalEntries++
                    val name = entry.name
                    when {
                        name.endsWith(".dex") && !name.contains('/') -> dexCount++
                        name == "resources.arsc" -> hasResourcesArsc = true
                        name.startsWith("kotlin/") || name.endsWith(".kotlin_builtins") -> hasKotlinMeta = true
                        name.startsWith("lib/") && name.endsWith(".so") -> {
                            nativeLibsCount++
                            val parts = name.split('/')
                            if (parts.size >= 3) abis.add(parts[1])
                        }
                    }
                }
            }
        }

        return ApkFileForensics(
            fileSizeBytes = apkFile.length(),
            crc32Hex = "%08x".format(crc.value),
            md5Hex = CertificateCryptoExtractor.bytesToHex(md5.digest()),
            sha1Hex = CertificateCryptoExtractor.bytesToHex(sha1.digest()),
            sha256Hex = CertificateCryptoExtractor.bytesToHex(sha256.digest()),
            sha512Hex = CertificateCryptoExtractor.bytesToHex(sha512.digest()),
            totalZipEntries = totalEntries,
            dexCount = dexCount,
            nativeLibrariesCount = nativeLibsCount,
            nativeAbis = abis.sorted(),
            hasResourcesArsc = hasResourcesArsc,
            hasKotlinMetadata = hasKotlinMeta
        )
    }
}
