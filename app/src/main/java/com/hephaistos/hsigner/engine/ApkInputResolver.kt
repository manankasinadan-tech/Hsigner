package com.hephaistos.hsigner.engine

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.OpenableColumns
import org.json.JSONArray
import java.io.Closeable
import java.io.File
import java.io.FileOutputStream
import java.util.UUID

class StorageAccessDeniedException(
    val uriSpec: String,
    val decodedPath: String?,
    val needsAllFilesAccess: Boolean,
    message: String
) : SecurityException(message)

/**
 * Résout des entrées hétérogènes (URIs content:// du file_picker HEPHAISTOS, file://,
 * chemins locaux directs, tableaux JSON) vers des fichiers exploitables par ApkVerifier.
 *
 * Stratégie multi-couches :
 * 1) Lecture directe si chemin local / file:// lisible.
 * 2) Lecture via ContentResolver.openInputStream(uri) si l'hôte a accordé FLAG_GRANT_READ_URI_PERMISSION.
 * 3) Fallback automatique vers le chemin décodé /storage/emulated/0/... si l'hôte a transmis l'URI
 *    en chaîne dans PARAMS_JSON sans ClipData grant et que HSIGNER dispose de l'accès fichiers.
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
        val decodedLocalPath = decodeSafDocumentPath(uri)
        val displayPath = resolveDisplayPath(context, uri, decodedLocalPath) ?: trimmed
        val tmpDir = File(context.cacheDir, "hsigner_tmp").apply { mkdirs() }
        val tmpFile = File(tmpDir, "input_${UUID.randomUUID()}.$extension")

        try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(tmpFile).use { output ->
                    input.copyTo(output, bufferSize = 64 * 1024)
                }
                return Triple(tmpFile, displayPath, tmpFile)
            }
        } catch (sec: SecurityException) {
            runCatching { tmpFile.delete() }
            // 3. Fallback direct si le chemin réel est accessible (ex: MANAGE_EXTERNAL_STORAGE accordé)
            if (!decodedLocalPath.isNullOrBlank()) {
                val directFile = File(decodedLocalPath)
                if (directFile.exists() && directFile.canRead()) {
                    return Triple(directFile, directFile.absolutePath, null)
                }
            }
            val needsAllFiles = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
                !Environment.isExternalStorageManager()
            val reason = if (needsAllFiles) {
                "Permission fichier requise : HEPHAISTOS n'a pas transmis l'autorisation de lecture sur l'URI ($displayPath). Activez « Accès à tous les fichiers » pour HSIGNER dans Paramètres Android puis relancez Verify."
            } else {
                "Accès refusé par Android pour $displayPath : ${sec.message}"
            }
            throw StorageAccessDeniedException(
                uriSpec = trimmed,
                decodedPath = decodedLocalPath,
                needsAllFilesAccess = needsAllFiles,
                message = reason
            )
        }

        // Si openInputStream a retourné null, tenter le chemin décodé
        if (!decodedLocalPath.isNullOrBlank()) {
            val directFile = File(decodedLocalPath)
            if (directFile.exists() && directFile.canRead()) {
                return Triple(directFile, directFile.absolutePath, null)
            }
        }

        throw IllegalStateException("Flux illisible pour l'URI : $trimmed")
    }

    /**
     * Décode une URI SAF (ExternalStorageProvider / DownloadsProvider) en chemin local réel
     * ex: content://com.android.externalstorage.documents/document/primary%3ADownload%2Fapp.apk
     *  -> /storage/emulated/0/Download/app.apk
     */
    fun decodeSafDocumentPath(uri: Uri): String? {
        val authority = uri.authority ?: return null
        val pathSegments = uri.pathSegments ?: emptyList()

        if (authority == "com.android.externalstorage.documents") {
            val docId = when {
                pathSegments.size >= 2 && pathSegments[pathSegments.size - 2] == "document" ->
                    pathSegments.last()
                else -> uri.lastPathSegment
            } ?: return null

            val colonIdx = docId.indexOf(':')
            if (colonIdx <= 0) return null
            val volumeId = docId.substring(0, colonIdx)
            val relativePath = docId.substring(colonIdx + 1).trimStart('/')
            return if (volumeId.equals("primary", ignoreCase = true)) {
                if (relativePath.isBlank()) "/storage/emulated/0" else "/storage/emulated/0/$relativePath"
            } else {
                if (relativePath.isBlank()) "/storage/$volumeId" else "/storage/$volumeId/$relativePath"
            }
        }

        if (authority == "com.android.providers.downloads.documents") {
            val docId = uri.lastPathSegment ?: return null
            if (docId.startsWith("raw:")) {
                return docId.removePrefix("raw:")
            }
        }

        return null
    }

    private fun resolveDisplayPath(context: Context, uri: Uri, decodedLocalPath: String?): String? {
        if (uri.scheme == "file") return uri.path
        if (!decodedLocalPath.isNullOrBlank()) return decodedLocalPath

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
        return displayName ?: uri.toString()
    }
}
