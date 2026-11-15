package com.hephaistos.hsigner.engine

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * Parseur léger de AndroidManifest.xml binaire (AXML) autonome (compatible JVM et Android).
 * Extrait package, versionName, versionCode, minSdk, targetSdk, compileSdk, label,
 * flags de sécurité (debuggable, allowBackup, usesCleartextTraffic, testOnly) et permissions.
 */
object BinaryXmlManifestParser {

    data class ParsedManifest(
        val packageName: String? = null,
        val versionName: String? = null,
        val versionCode: Long? = null,
        val appLabel: String? = null,
        val minSdkVersion: Int? = null,
        val targetSdkVersion: Int? = null,
        val compileSdkVersion: Int? = null,
        val debuggable: Boolean? = null,
        val allowBackup: Boolean? = null,
        val usesCleartextTraffic: Boolean? = null,
        val testOnly: Boolean? = null,
        val permissions: List<String> = emptyList()
    )

    private const val CHUNK_AXML_FILE = 0x00080003
    private const val CHUNK_STRING_POOL = 0x001C0001
    private const val CHUNK_XML_RESOURCE_MAP = 0x00080180
    private const val CHUNK_XML_START_TAG = 0x00100102
    private const val FLAG_UTF8 = 1 shl 8

    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12

    fun parseFromApk(apkFile: File): ParsedManifest {
        return runCatching {
            ZipFile(apkFile).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return ParsedManifest()
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                parseBytes(bytes)
            }
        }.getOrDefault(ParsedManifest())
    }

    fun parseBytes(data: ByteArray): ParsedManifest {
        if (data.size < 8) return ParsedManifest()
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val fileType = buf.getInt(0)
        if (fileType != CHUNK_AXML_FILE) return ParsedManifest()

        var strings: List<String> = emptyList()
        var resIds: IntArray = IntArray(0)

        var packageName: String? = null
        var versionName: String? = null
        var versionCodeLow: Long? = null
        var versionCodeMajor: Long? = null
        var appLabel: String? = null
        var minSdk: Int? = null
        var targetSdk: Int? = null
        var compileSdk: Int? = null
        var debuggable: Boolean? = null
        var allowBackup: Boolean? = null
        var usesCleartextTraffic: Boolean? = null
        var testOnly: Boolean? = null
        val permissions = linkedSetOf<String>()

        var offset = 8
        while (offset + 8 <= data.size) {
            val chunkType = buf.getInt(offset)
            val chunkSize = buf.getInt(offset + 4)
            if (chunkSize < 8 || offset + chunkSize > data.size) break

            when (chunkType) {
                CHUNK_STRING_POOL -> {
                    strings = readStringPool(data, offset, chunkSize)
                }
                CHUNK_XML_RESOURCE_MAP -> {
                    val count = (chunkSize - 8) / 4
                    resIds = IntArray(count) { i -> buf.getInt(offset + 8 + i * 4) }
                }
                CHUNK_XML_START_TAG -> {
                    if (offset + 36 <= data.size) {
                        val nameIdx = buf.getInt(offset + 20)
                        val attrCount = buf.getShort(offset + 28).toInt() and 0xFFFF
                        val tagName = strings.getOrNull(nameIdx).orEmpty()
                        var attrOff = offset + 36

                        for (i in 0 until attrCount) {
                            if (attrOff + 20 > offset + chunkSize) break
                            val attrNameIdx = buf.getInt(attrOff + 4)
                            val rawValIdx = buf.getInt(attrOff + 8)
                            val valueType = (buf.get(attrOff + 15).toInt() and 0xFF)
                            val valueData = buf.getInt(attrOff + 16)

                            val attrName = strings.getOrNull(attrNameIdx).orEmpty()
                            val attrResId = resIds.getOrNull(attrNameIdx) ?: 0

                            when (tagName) {
                                "manifest" -> {
                                    when {
                                        attrName == "package" -> {
                                            packageName = resolveString(strings, rawValIdx, valueType, valueData)
                                        }
                                        attrName == "versionCode" || attrResId == 0x0101021b -> {
                                            if (valueType == TYPE_INT_DEC || valueType == TYPE_INT_HEX) {
                                                versionCodeLow = valueData.toLong() and 0xFFFFFFFFL
                                            }
                                        }
                                        attrName == "versionCodeMajor" || attrResId == 0x01010576 -> {
                                            if (valueType == TYPE_INT_DEC || valueType == TYPE_INT_HEX) {
                                                versionCodeMajor = valueData.toLong() and 0xFFFFFFFFL
                                            }
                                        }
                                        attrName == "versionName" || attrResId == 0x0101021c -> {
                                            versionName = resolveString(strings, rawValIdx, valueType, valueData)
                                        }
                                        attrName == "compileSdkVersion" || attrResId == 0x01010572 -> {
                                            if (valueType == TYPE_INT_DEC || valueType == TYPE_INT_HEX) {
                                                compileSdk = valueData
                                            }
                                        }
                                    }
                                }
                                "application" -> {
                                    when {
                                        attrName == "label" || attrResId == 0x01010001 -> {
                                            val resolved = resolveString(strings, rawValIdx, valueType, valueData)
                                            if (!resolved.isNullOrBlank()) {
                                                appLabel = resolved
                                            }
                                        }
                                        attrName == "debuggable" || attrResId == 0x0101000f -> {
                                            if (valueType == TYPE_INT_BOOLEAN || valueType == TYPE_INT_DEC) {
                                                debuggable = valueData != 0
                                            }
                                        }
                                        attrName == "allowBackup" || attrResId == 0x01010280 -> {
                                            if (valueType == TYPE_INT_BOOLEAN || valueType == TYPE_INT_DEC) {
                                                allowBackup = valueData != 0
                                            }
                                        }
                                        attrName == "usesCleartextTraffic" || attrResId == 0x010104ec -> {
                                            if (valueType == TYPE_INT_BOOLEAN || valueType == TYPE_INT_DEC) {
                                                usesCleartextTraffic = valueData != 0
                                            }
                                        }
                                        attrName == "testOnly" || attrResId == 0x01010272 -> {
                                            if (valueType == TYPE_INT_BOOLEAN || valueType == TYPE_INT_DEC) {
                                                testOnly = valueData != 0
                                            }
                                        }
                                    }
                                }
                                "uses-sdk" -> {
                                    when {
                                        attrName == "minSdkVersion" || attrResId == 0x0101020c -> {
                                            if (valueType == TYPE_INT_DEC || valueType == TYPE_INT_HEX) {
                                                minSdk = valueData
                                            }
                                        }
                                        attrName == "targetSdkVersion" || attrResId == 0x01010270 -> {
                                            if (valueType == TYPE_INT_DEC || valueType == TYPE_INT_HEX) {
                                                targetSdk = valueData
                                            }
                                        }
                                    }
                                }
                                "uses-permission", "uses-permission-sdk-23" -> {
                                    if (attrName == "name" || attrResId == 0x01010003) {
                                        val perm = resolveString(strings, rawValIdx, valueType, valueData)
                                        if (!perm.isNullOrBlank()) permissions.add(perm)
                                    }
                                }
                            }
                            attrOff += 20
                        }
                    }
                }
            }
            offset += chunkSize
        }

        val combinedVersionCode = when {
            versionCodeLow != null && versionCodeMajor != null ->
                (versionCodeMajor shl 32) or versionCodeLow
            versionCodeLow != null -> versionCodeLow
            else -> null
        }

        return ParsedManifest(
            packageName = packageName,
            versionName = versionName,
            versionCode = combinedVersionCode,
            appLabel = appLabel,
            minSdkVersion = minSdk,
            targetSdkVersion = targetSdk,
            compileSdkVersion = compileSdk,
            debuggable = debuggable,
            allowBackup = allowBackup,
            usesCleartextTraffic = usesCleartextTraffic,
            testOnly = testOnly,
            permissions = permissions.toList()
        )
    }

    private fun resolveString(
        strings: List<String>,
        rawValIdx: Int,
        valueType: Int,
        valueData: Int
    ): String? {
        if (rawValIdx >= 0 && rawValIdx < strings.size) return strings[rawValIdx]
        if (valueType == TYPE_STRING && valueData >= 0 && valueData < strings.size) {
            return strings[valueData]
        }
        return null
    }

    private fun readStringPool(data: ByteArray, chunkStart: Int, chunkSize: Int): List<String> {
        if (chunkStart + 28 > data.size) return emptyList()
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val stringCount = buf.getInt(chunkStart + 8)
        val flags = buf.getInt(chunkStart + 16)
        val stringsOffset = buf.getInt(chunkStart + 20)
        val isUtf8 = (flags and FLAG_UTF8) != 0

        val result = ArrayList<String>(stringCount.coerceAtLeast(0))
        val poolStart = chunkStart + stringsOffset
        val offsetsStart = chunkStart + 28

        for (i in 0 until stringCount) {
            if (offsetsStart + i * 4 + 4 > chunkStart + chunkSize) break
            val strRelOffset = buf.getInt(offsetsStart + i * 4)
            var pos = poolStart + strRelOffset
            if (pos < poolStart || pos >= chunkStart + chunkSize) {
                result.add("")
                continue
            }
            if (isUtf8) {
                val (_, next1) = readLength8(data, pos)
                val (byteLen, next2) = readLength8(data, next1)
                pos = next2
                val safeLen = byteLen.coerceAtMost((chunkStart + chunkSize - pos).coerceAtLeast(0))
                result.add(String(data, pos, safeLen, Charsets.UTF_8))
            } else {
                val (charLen, next) = readLength16(data, pos)
                pos = next
                val byteLen = (charLen * 2).coerceAtMost((chunkStart + chunkSize - pos).coerceAtLeast(0))
                result.add(String(data, pos, byteLen, Charsets.UTF_16LE))
            }
        }
        return result
    }

    private fun readLength8(data: ByteArray, offset: Int): Pair<Int, Int> {
        if (offset >= data.size) return 0 to offset
        val first = data[offset].toInt() and 0xFF
        return if ((first and 0x80) != 0 && offset + 1 < data.size) {
            val second = data[offset + 1].toInt() and 0xFF
            (((first and 0x7F) shl 8) or second) to (offset + 2)
        } else {
            first to (offset + 1)
        }
    }

    private fun readLength16(data: ByteArray, offset: Int): Pair<Int, Int> {
        if (offset + 1 >= data.size) return 0 to offset
        val first = (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)
        return if ((first and 0x8000) != 0 && offset + 3 < data.size) {
            val second = (data[offset + 2].toInt() and 0xFF) or ((data[offset + 3].toInt() and 0xFF) shl 8)
            (((first and 0x7FFF) shl 16) or second) to (offset + 4)
        } else {
            first to (offset + 2)
        }
    }
}
