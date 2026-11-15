package com.hephaistos.hsigner.engine

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
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
 * inspect_capabilities, open_storage_settings), partagé entre ModuleEngineService et HsignerContentProvider.
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
            HephaistosContract.CMD_OPEN_STORAGE_SETTINGS ->
                handleOpenStorageSettings(sourcePackage, emitBroadcasts)
            else -> {
                val errMsg = "Commande inconnue : '$commandId'. Commandes supportées : verify_apk, get_readme, export_readme_file, inspect_capabilities, open_storage_settings."
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
        val includeApkFileHashes = params.optBoolean("include_apk_file_hashes", true)
        val includeManifestAudit = params.optBoolean("include_manifest_audit", true)
        val detailLevel = params.optString("detail_level", "ultra_complet").ifBlank { "ultra_complet" }
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

        val resolvedInputs = try {
            ApkInputResolver.resolveAll(context, rawApkInputs, rawIdsigInputs)
        } catch (permErr: StorageAccessDeniedException) {
            val errMsg = permErr.message ?: "Accès au fichier refusé par Android."
            if (emitBroadcasts) {
                bridge.logErr(errMsg, sourcePackage)
                bridge.progress(
                    taskId = taskId,
                    title = "HSIGNER — Permission requise",
                    message = errMsg,
                    progress = 100,
                    completed = true,
                    error = errMsg,
                    canCancel = false,
                    targetSourcePackage = sourcePackage
                )
                if (permErr.needsAllFilesAccess) {
                    bridge.showPopup(
                        popupId = "storage_permission_popup",
                        title = "Permission Accès Fichiers requise",
                        message = "HEPHAISTOS n'a pas transmis l'autorisation de lecture sur ce fichier. Autorisez « Accès à tous les fichiers » pour HSIGNER dans les paramètres Android, puis relancez Verify.",
                        confirmLabel = "Ouvrir Paramètres",
                        cancelLabel = "Fermer",
                        commandId = HephaistosContract.CMD_OPEN_STORAGE_SETTINGS
                    )
                }
                bridge.sendCommandResult(HephaistosContract.CMD_VERIFY_APK, sourcePackage, null, errMsg)
            }
            return JSONObject().apply {
                put("status", "permission_required")
                put("error", errMsg)
                permErr.decodedPath?.let { put("decoded_path", it) }
            }
        }

        val analyzer = ApkSignatureAnalyzer(context)
        val resultsArray = JSONArray()
        val combinedText = StringBuilder()
        var allVerified = true
        var lastSummary = ""
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
                        includeRawBits = includeRawBits,
                        includeApkFileHashes = includeApkFileHashes,
                        includeManifestAudit = includeManifestAudit
                    )
                    if (!report.isVerified) allVerified = false
                    lastSummary = "${report.metadata.appName} — ${report.schemeSummary} (${report.certificates.size} cert.)"

                    val terminalBlock = SignatureReportFormatter.formatTerminalReport(report, detailLevel)
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
                        resultsArray.put(
                            SignatureReportFormatter.toJson(
                                report = report,
                                includeTerminalText = true,
                                detailLevel = detailLevel
                            )
                        )
                    }
                }
            }

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
                val summaryMsg = if (resolvedInputs.size == 1 && lastSummary.isNotBlank()) {
                    "$lastSummary — Ouvrez le terminal (>_) pour consulter tous les détails."
                } else {
                    "${resolvedInputs.size} APK(s) analysé(s) — ${if (allVerified) "Toutes signatures valides" else "Alerte signature détectée"} (Ouvrez le terminal >_)"
                }
                bridge.progress(
                    taskId = taskId,
                    title = "HSIGNER — Terminé",
                    message = summaryMsg,
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

    private fun handleOpenStorageSettings(
        sourcePackage: String?,
        emitBroadcasts: Boolean
    ): JSONObject {
        val opened = runCatching {
            val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Intent(
                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:${context.packageName}")
                )
            } else {
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.parse("package:${context.packageName}")
                )
            }.apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            true
        }.getOrElse {
            runCatching {
                val fallback = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(fallback)
                true
            }.getOrDefault(false)
        }

        val resultJson = JSONObject().apply {
            put("status", if (opened) "success" else "error")
            put("settings_opened", opened)
        }
        if (emitBroadcasts) {
            if (opened) {
                bridge.logInfo("Paramètres Android ouverts : activez « Accès à tous les fichiers » pour HSIGNER puis relancez Verify.", sourcePackage)
            } else {
                bridge.logErr("Impossible d'ouvrir automatiquement les paramètres. Ouvrez Paramètres > Applications > HSIGNER > Accès spéciaux manuellement.", sourcePackage)
            }
            bridge.sendCommandResult(HephaistosContract.CMD_OPEN_STORAGE_SETTINGS, sourcePackage, resultJson)
        }
        return resultJson
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
        val allFilesAccess = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { android.os.Environment.isExternalStorageManager() }.getOrDefault(false)
        } else {
            true
        }
        val siblingModules = runCatching {
            com.hephaistos.hsigner.protocol.HephaistosModuleClient(context)
                .discoverModules()
                .map { it.packageName }
        }.getOrDefault(emptyList())

        val diagnosticText = buildString {
            appendLine("=== DIAGNOSTIC MOTEUR HSIGNER ===")
            appendLine("Package : ${HephaistosContract.MODULE_PACKAGE} (v1.0.0)")
            appendLine("Protocole HEPHAISTOS : v1.0")
            appendLine("Accès direct fichiers (All Files Access) : ${if (allFilesAccess) "AUTORISÉ" else "NON AUTORISÉ (utilisez le bouton 'Autoriser l'accès stockage' si besoin)"}")
            appendLine("Schémas supportés : V1 (JAR), V2, V3, V3.1 (Key Rotation), V4 (.idsig), SourceStamp")
            appendLine("Empreintes calculées : CRC32, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SPKI Pin")
            appendLine("Modules HEPHAISTOS détectés (${siblingModules.size}) : ${if (siblingModules.isEmpty()) "Aucun" else siblingModules.joinToString(", ")}")
        }.trimEnd()

        val resultJson = JSONObject().apply {
            put("status", "success")
            put("module", HephaistosContract.MODULE_PACKAGE)
            put("version", "1.0.0")
            put("protocol_version", "1.0")
            put("all_files_access_granted", allFilesAccess)
            put("discovered_modules", JSONArray(siblingModules))
            put("supported_schemes", JSONArray(listOf("V1", "V2", "V3", "V3.1", "V4")))
            put("supported_digests", JSONArray(listOf("CRC32", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512")))
            put("commands", JSONArray(listOf(
                HephaistosContract.CMD_VERIFY_APK,
                HephaistosContract.CMD_GET_README,
                HephaistosContract.CMD_EXPORT_README_FILE,
                HephaistosContract.CMD_INSPECT_CAPABILITIES,
                HephaistosContract.CMD_OPEN_STORAGE_SETTINGS
            )))
            put("diagnostic_report", diagnosticText)
            put("manifest", runCatching { JSONObject(readRawManifestString()) }.getOrNull())
        }

        if (emitBroadcasts) {
            bridge.logOut(diagnosticText, sourcePackage)
            bridge.progress(
                taskId = "diag_${System.currentTimeMillis()}",
                title = "HSIGNER — Diagnostic",
                message = "Accès fichiers : ${if (allFilesAccess) "OK" else "Requis"} | Modules : ${siblingModules.size} (Détails dans le terminal >_)",
                progress = 100,
                completed = true,
                canCancel = false,
                targetSourcePackage = sourcePackage
            )
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
