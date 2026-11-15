package com.hephaistos.hsigner.engine

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import com.hephaistos.hsigner.R
import com.hephaistos.hsigner.protocol.HephaistosBridge
import com.hephaistos.hsigner.protocol.HephaistosContract
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Orchestrateur métier des commandes HSIGNER (verify_apk, get_readme, export_readme_file,
 * inspect_capabilities), partagé entre ModuleEngineService et HsignerContentProvider.
 */
class HsignerCommandProcessor(
    private val context: Context,
    private val bridge: HephaistosBridge = HephaistosBridge(context)
) {

    fun executeCommand(
        commandId: String,
        paramsJsonRaw: String?,
        sourcePackage: String?,
        taskId: String = UUID.randomUUID().toString(),
        isCancelled: () -> Boolean = { false },
        emitBroadcasts: Boolean = true
    ): JSONObject {
        val params = runCatching {
            if (paramsJsonRaw.isNullOrBlank()) JSONObject() else JSONObject(paramsJsonRaw)
        }.getOrElse { JSONObject() }

        return when (commandId) {
            HephaistosContract.CMD_VERIFY_APK ->
                handleVerifyApk(params, sourcePackage, taskId, isCancelled, emitBroadcasts)
            HephaistosContract.CMD_GET_README ->
                handleGetReadme(params, sourcePackage, emitBroadcasts)
            HephaistosContract.CMD_EXPORT_README_FILE ->
                handleExportReadmeFile(params, sourcePackage, emitBroadcasts)
            HephaistosContract.CMD_INSPECT_CAPABILITIES ->
                handleInspectCapabilities(sourcePackage, emitBroadcasts)
            else -> {
                val errMsg = "Commande inconnue : '$commandId'. Commandes supportées : verify_apk, get_readme, export_readme_file, inspect_capabilities."
                if (emitBroadcasts) {
                    bridge.logErr(errMsg, sourcePackage)
                    bridge.sendCommandResult(commandId, sourcePackage, null, errMsg)
                }
                JSONObject().apply {
                    put("status", "error")
                    put("error", errMsg)
                }
            }
        }
    }

    private fun handleVerifyApk(
        params: JSONObject,
        sourcePackage: String?,
        taskId: String,
        isCancelled: () -> Boolean,
        emitBroadcasts: Boolean
    ): JSONObject {
        val rawApkInputs = ApkInputResolver.parseUriList(
            params.opt("apk_uris") ?: params.opt("apk_uri") ?: params.opt("paths") ?: params.opt("path")
        )
        val rawIdsigInputs = ApkInputResolver.parseUriList(
            params.opt("idsig_uris") ?: params.opt("idsig_uri")
        )
        val includeRawBits = params.optBoolean("include_raw_bits", true)
        val includeJson = params.optBoolean("include_json", true)

        if (rawApkInputs.isEmpty()) {
            val err = "Aucun fichier APK sélectionné. Veuillez choisir au moins un fichier .apk."
            if (emitBroadcasts) {
                bridge.logErr(err, sourcePackage)
                bridge.progress(
                    taskId = taskId,
                    title = "HSIGNER",
                    message = err,
                    progress = 100,
                    completed = true,
                    error = err,
                    canCancel = false,
                    targetSourcePackage = sourcePackage
                )
                bridge.sendCommandResult(HephaistosContract.CMD_VERIFY_APK, sourcePackage, null, err)
            }
            return JSONObject().apply {
                put("status", "error")
                put("error", err)
            }
        }

        if (emitBroadcasts) {
            bridge.logInfo("HSIGNER : préparation de l'analyse pour ${rawApkInputs.size} fichier(s)…", sourcePackage)
            bridge.progress(
                taskId = taskId,
                title = "HSIGNER — Vérification APK",
                message = "Résolution de ${rawApkInputs.size} fichier(s)…",
                progress = 5,
                completed = false,
                canCancel = true,
                targetSourcePackage = sourcePackage
            )
        }

        val resolvedInputs = ApkInputResolver.resolveAll(context, rawApkInputs, rawIdsigInputs)
        val analyzer = ApkSignatureAnalyzer(context)
        val resultsArray = JSONArray()
        val combinedText = StringBuilder()
        var allVerified = true
        val sharedUris = mutableListOf<Uri>()

        try {
            val total = resolvedInputs.size
            for ((idx, item) in resolvedInputs.withIndex()) {
                if (isCancelled()) {
                    val cancelMsg = "Vérification annulée par l'utilisateur (tâche $taskId)."
                    if (emitBroadcasts) {
                        bridge.logErr(cancelMsg, sourcePackage)
                        bridge.progress(
                            taskId = taskId,
                            title = "HSIGNER — Annulé",
                            message = cancelMsg,
                            progress = 100,
                            completed = true,
                            error = cancelMsg,
                            canCancel = false,
                            targetSourcePackage = sourcePackage
                        )
                        bridge.sendCommandResult(HephaistosContract.CMD_VERIFY_APK, sourcePackage, null, cancelMsg)
                    }
                    return JSONObject().apply {
                        put("status", "cancelled")
                        put("error", cancelMsg)
                    }
                }

                item.use { resolved ->
                    val pct = (((idx + 0.5) / total) * 85.0).toInt().coerceIn(10, 95)
                    if (emitBroadcasts) {
                        bridge.progress(
                            taskId = taskId,
                            title = "HSIGNER — Analyse (${idx + 1}/$total)",
                            message = "Inspection de ${File(resolved.displayPath).name}…",
                            progress = pct,
                            completed = false,
                            canCancel = true,
                            targetSourcePackage = sourcePackage
                        )
                    }

                    val report = analyzer.analyze(
                        apkFile = resolved.apkFile,
                        displayPath = resolved.displayPath,
                        explicitIdsigFile = resolved.idsigFile,
                        includeRawBits = includeRawBits
                    )
                    if (!report.isVerified) allVerified = false

                    val terminalBlock = SignatureReportFormatter.formatTerminalReport(report)
                    if (combinedText.isNotEmpty()) {
                        combinedText.appendLine()
                        combinedText.appendLine("================================================================================")
                        combinedText.appendLine()
                    }
                    combinedText.append(terminalBlock)

                    if (emitBroadcasts) {
                        bridge.logOut(terminalBlock, sourcePackage)
                        if (idx < resolvedInputs.lastIndex) {
                            bridge.logOut(
                                "================================================================================",
                                sourcePackage
                            )
                        }
                    }

                    if (includeJson) {
                        resultsArray.put(SignatureReportFormatter.toJson(report, includeTerminalText = true))
                    }
                }
            }

            // Export fichier rapport complet pour consultation ou contournement de limite IPC
            val reportFile = writeExportFile("hsigner_exports", "HSIGNER_REPORT_${System.currentTimeMillis()}.txt", combinedText.toString())
            val reportUri = getFileProviderUri(reportFile)
            sharedUris.add(reportUri)

            val responseJson = JSONObject().apply {
                put("status", "success")
                put("module", HephaistosContract.MODULE_PACKAGE)
                put("total_apks", resolvedInputs.size)
                put("all_verified", allVerified)
                put("export_report_uri", reportUri.toString())
                if (includeJson) {
                    put("results", resultsArray)
                }
                put("terminal_report", combinedText.toString())
            }

            if (emitBroadcasts) {
                bridge.progress(
                    taskId = taskId,
                    title = "HSIGNER — Terminé",
                    message = "${resolvedInputs.size} APK(s) analysé(s) — ${if (allVerified) "Toutes signatures valides" else "Alerte signature détectée"}",
                    progress = 100,
                    completed = true,
                    canCancel = false,
                    targetSourcePackage = sourcePackage
                )
                bridge.sendCommandResult(
                    commandId = HephaistosContract.CMD_VERIFY_APK,
                    sourcePackage = sourcePackage,
                    resultJson = responseJson,
                    sharedUris = sharedUris
                )
            }
            return responseJson
        } finally {
            resolvedInputs.forEach { runCatching { it.close() } }
        }
    }

    private fun handleGetReadme(
        params: JSONObject,
        sourcePackage: String?,
        emitBroadcasts: Boolean
    ): JSONObject {
        val rawManifest = readRawManifestString()
        val markdown = ReadmeDocumentGenerator.buildMarkdownReadme(rawManifest)

        val readmeFile = writePersistentDoc(ReadmeDocumentGenerator.README_FILENAME, markdown)
        val specFile = writePersistentDoc(ReadmeDocumentGenerator.SPEC_FILENAME, rawManifest)

        val readmeUri = getFileProviderUri(readmeFile)
        val specUri = getFileProviderUri(specFile)
        val providerReadmeUri = "content://${HephaistosContract.CONTENT_PROVIDER_AUTHORITY}/readme"

        val resultJson = JSONObject().apply {
            put("status", "success")
            put("module", HephaistosContract.MODULE_PACKAGE)
            put("filename", ReadmeDocumentGenerator.README_FILENAME)
            put("readme_uri", readmeUri.toString())
            put("spec_uri", specUri.toString())
            put("content_provider_uri", providerReadmeUri)
            put("readme_markdown", markdown)
            put("protocol_spec", runCatching { JSONObject(rawManifest) }.getOrNull() ?: rawManifest)
        }

        if (emitBroadcasts) {
            bridge.logOut(markdown, sourcePackage)
            bridge.logInfo("Document téléchargeable prêt : $readmeUri (ou $providerReadmeUri)", sourcePackage)

            if (params.optBoolean("open_popup", true)) {
                bridge.showPopup(
                    popupId = "readme_download_popup",
                    title = "HSIGNER — Documentation Inter-Modulaire",
                    message = "Le guide complet (actions, extras, schémas JSON, commandes terminales et consignes IA) est affiché dans le terminal. Télécharger ${ReadmeDocumentGenerator.README_FILENAME} ?",
                    confirmLabel = "Télécharger",
                    cancelLabel = "Fermer",
                    commandId = HephaistosContract.CMD_EXPORT_README_FILE,
                    downloadUri = readmeUri
                )
            }

            bridge.sendCommandResult(
                commandId = HephaistosContract.CMD_GET_README,
                sourcePackage = sourcePackage,
                resultJson = resultJson,
                sharedUris = listOf(readmeUri, specUri)
            )
        }

        return resultJson
    }

    private fun handleExportReadmeFile(
        params: JSONObject,
        sourcePackage: String?,
        emitBroadcasts: Boolean
    ): JSONObject {
        val format = params.optString("format", "markdown").lowercase()
        val targetUriStr = params.optString("target_uri", "").trim()
        val rawManifest = readRawManifestString()

        val (filename, content) = if (format == "json") {
            ReadmeDocumentGenerator.SPEC_FILENAME to rawManifest
        } else {
            ReadmeDocumentGenerator.README_FILENAME to ReadmeDocumentGenerator.buildMarkdownReadme(rawManifest)
        }

        val docFile = writePersistentDoc(filename, content)
        val downloadUri = getFileProviderUri(docFile)

        var writtenToTarget = false
        if (targetUriStr.isNotBlank()) {
            runCatching {
                context.contentResolver.openOutputStream(Uri.parse(targetUriStr))?.use { out ->
                    out.write(content.toByteArray(Charsets.UTF_8))
                }
                writtenToTarget = true
            }
        }

        val resultJson = JSONObject().apply {
            put("status", "success")
            put("filename", filename)
            put("download_uri", downloadUri.toString())
            put("provider_uri", "content://${HephaistosContract.CONTENT_PROVIDER_AUTHORITY}/readme")
            put("local_path", docFile.absolutePath)
            put("byte_size", content.toByteArray(Charsets.UTF_8).size)
            put("written_to_target", writtenToTarget)
        }

        if (emitBroadcasts) {
            bridge.logInfo(
                "Readme exporté ($filename, ${docFile.length()} octets) -> URI de téléchargement : $downloadUri",
                sourcePackage
            )
            bridge.sendCommandResult(
                commandId = HephaistosContract.CMD_EXPORT_README_FILE,
                sourcePackage = sourcePackage,
                resultJson = resultJson,
                sharedUris = listOf(downloadUri)
            )
        }

        return resultJson
    }

    private fun handleInspectCapabilities(
        sourcePackage: String?,
        emitBroadcasts: Boolean
    ): JSONObject {
        val resultJson = JSONObject().apply {
            put("status", "success")
            put("module", HephaistosContract.MODULE_PACKAGE)
            put("version", "1.0.0")
            put("protocol_version", "1.0")
            put("supported_schemes", JSONArray(listOf("V1", "V2", "V3", "V3.1", "V4")))
            put("supported_digests", JSONArray(listOf("CRC32", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512")))
            put("commands", JSONArray(listOf(
                HephaistosContract.CMD_VERIFY_APK,
                HephaistosContract.CMD_GET_README,
                HephaistosContract.CMD_EXPORT_README_FILE,
                HephaistosContract.CMD_INSPECT_CAPABILITIES
            )))
            put("manifest", runCatching { JSONObject(readRawManifestString()) }.getOrNull())
        }

        if (emitBroadcasts) {
            bridge.sendCommandResult(
                commandId = HephaistosContract.CMD_INSPECT_CAPABILITIES,
                sourcePackage = sourcePackage,
                resultJson = resultJson
            )
        }
        return resultJson
    }

    fun readRawManifestString(): String {
        return context.resources.openRawResource(R.raw.hephaistos_manifest)
            .bufferedReader(Charsets.UTF_8)
            .use { it.readText() }
    }

    fun writePersistentDoc(filename: String, content: String): File {
        val dir = File(context.filesDir, "hsigner_docs").apply { mkdirs() }
        val file = File(dir, filename)
        file.writeText(content, Charsets.UTF_8)
        return file
    }

    private fun writeExportFile(subDir: String, filename: String, content: String): File {
        val dir = File(context.cacheDir, subDir).apply { mkdirs() }
        val file = File(dir, filename)
        file.writeText(content, Charsets.UTF_8)
        return file
    }

    private fun getFileProviderUri(file: File): Uri {
        return FileProvider.getUriForFile(context, HephaistosContract.FILE_PROVIDER_AUTHORITY, file)
    }
}
