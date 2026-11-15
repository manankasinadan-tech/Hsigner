package com.hephaistos.hsigner.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import org.json.JSONArray
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.util.UUID

/**
 * Résout des entrées hétérogènes (URIs content:// du file_picker HEPHAISTOS, file://,
 * chemins locaux directs, tableaux JSON) vers des fichiers exploitables par ApkVerifier,
 * sans nécessiter READ_EXTERNAL_STORAGE.
 */
object ApkInputResolver {

    data class ResolvedApkInput(
        val originalSpec: String,
        val displayPath: String,
        val apkFile: File,
        val idsigFile: File?,
        private val tempFiles: List<File>
    ) : Closeable {
        override fun close() {
            tempFiles.forEach { runCatching { it.delete() } }
        }
    }

    /**
     * Extrait une liste plate de chaînes depuis un champ JSON qui peut être
     * un JSONArray, une chaîne JSON sérialisée, ou une liste séparée par virgules/lignes.
     */
    fun parseUriList(rawValue: Any?): List<String> {
        return when (rawValue) {
            null -> emptyList()
            is JSONArray -> buildList {
                for (i in 0 until rawValue.length()) {
                    val item = rawValue.optString(i).trim()
                    if (item.isNotBlank()) add(item)
                }
            }
            is String -> {
                val trimmed = rawValue.trim()
                if (trimmed.isBlank() || trimmed == "null") {
                    emptyList()
                } else if (trimmed.startsWith("[")) {
                    runCatching {
                        val arr = JSONArray(trimmed)
                        parseUriList(arr)
                    }.getOrElse { listOf(trimmed) }
                } else if (trimmed.contains("\n")) {
                    trimmed.lines().map { it.trim() }.filter { it.isNotBlank() }
                } else if (trimmed.contains(",") && !trimmed.startsWith("content://")) {
                    trimmed.split(",").map { it.trim() }.filter { it.isNotBlank() }
                } else {
                    listOf(trimmed)
                }
            }
            else -> listOf(rawValue.toString().trim()).filter { it.isNotBlank() }
        }
    }

    fun resolveAll(
        context: Context,
        rawInputs: List<String>,
        explicitIdsigInputs: List<String> = emptyList()
    ): List<ResolvedApkInput> {
        val apkSpecs = mutableListOf<String>()
        val idsigSpecs = mutableListOf<String>()
        idsigSpecs.addAll(explicitIdsigInputs)

        for (spec in rawInputs) {
            val lower = spec.lowercase()
            if (lower.endsWith(".idsig")) {
                idsigSpecs.add(spec)
            } else {
                apkSpecs.add(spec)
            }
        }

        // Pré-résolution des fichiers .idsig disponibles
        val resolvedIdsigs = idsigSpecs.mapNotNull { spec ->
            materializeSingle(context, spec, "idsig")?.let { spec to it }
        }

        return apkSpecs.map { apkSpec ->
            val (apkFile, displayPath, tempApk) = materializeSingle(context, apkSpec, "apk")
                ?: throw IllegalArgumentException("Impossible d'ouvrir le fichier APK : $apkSpec")

            val tempList = mutableListOf<File>()
            if (tempApk != null) tempList.add(tempApk)

            val apkBaseName = File(displayPath).nameWithoutExtension
            val matchedIdsig = resolvedIdsigs.firstOrNull { (idsigSpec, tuple) ->
                val idsigName = File(tuple.second).name
                idsigName.equals("${File(displayPath).name}.idsig", ignoreCase = true) ||
                    idsigName.equals("$apkBaseName.idsig", ignoreCase = true) ||
                    idsigSpec.contains(apkBaseName, ignoreCase = true)
            }?.second ?: if (resolvedIdsigs.size == 1 && apkSpecs.size == 1) {
                resolvedIdsigs.first().second
            } else null

            if (matchedIdsig?.third != null) {
                tempList.add(matchedIdsig.third!!)
            }

            ResolvedApkInput(
                originalSpec = apkSpec,
                displayPath = displayPath,
                apkFile = apkFile,
                idsigFile = matchedIdsig?.first,
                tempFiles = tempList
            )
        }
    }

    private fun materializeSingle(
        context: Context,
        spec: String,
        extension: String
    ): Triple<File, String, File?>? {
        val trimmed = spec.trim()
        if (trimmed.isBlank()) return null

        // 1. Chemin système direct ou file:// URI
        if (trimmed.startsWith("/") || trimmed.startsWith("file://")) {
            val path = if (trimmed.startsWith("file://")) {
                Uri.parse(trimmed).path ?: trimmed.removePrefix("file://")
            } else {
                trimmed
            }
            val directFile = File(path)
            if (directFile.exists() && directFile.canRead()) {
                return Triple(directFile, directFile.absolutePath, null)
            }
        }

        // 2. URI content:// (File Picker SAF de HEPHAISTOS)
        val uri = Uri.parse(trimmed)
        val displayPath = resolveDisplayPath(context, uri) ?: trimmed
        val tmpDir = File(context.cacheDir, "hsigner_tmp").apply { mkdirs() }
        val tmpFile = File(tmpDir, "input_${UUID.randomUUID()}.$extension")

        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(tmpFile).use { output ->
                input.copyTo(output, bufferSize = 64 * 1024)
            }
        } ?: throw IllegalStateException("Flux illisible pour l'URI : $trimmed")

        return Triple(tmpFile, displayPath, tmpFile)
    }

    private fun resolveDisplayPath(context: Context, uri: Uri): String? {
        if (uri.scheme == "file") return uri.path
        var displayName: String? = null
        runCatching {
            context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val dataIdx = cursor.getColumnIndex("_data")
                    if (dataIdx >= 0) {
                        val realPath = cursor.getString(dataIdx)
                        if (!realPath.isNullOrBlank()) return realPath
                    }
                    val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIdx >= 0) {
                        displayName = cursor.getString(nameIdx)
                    }
                }
            }
        }

        // Reconstruction propre des chemins DocumentsProvider standards (primary:...) si possible
        val lastSeg = uri.lastPathSegment
        if (!lastSeg.isNullOrBlank() && lastSeg.contains(":")) {
            val parts = lastSeg.split(":", limit = 2)
            if (parts.size == 2 && parts[0].equals("primary", ignoreCase = true)) {
                return "/storage/emulated/0/${parts[1]}"
            }
        }
        return displayName ?: uri.toString()
    }
}
