package com.hephaistos.hsigner.protocol

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import org.json.JSONObject

/**
 * Pont de communication officiel entre HSIGNER, HEPHAISTOS (com.hephaistos.launcher)
 * et tout autre module ou terminal de l'écosystème.
 */
class HephaistosBridge(private val context: Context) {

    /**
     * Émet un message dans le terminal intégré de HEPHAISTOS via com.hephaistos.action.LOG.
     * Découpe automatiquement les messages très longs pour éviter TransactionTooLargeException.
     */
    fun log(
        level: String,
        message: String,
        targetSourcePackage: String? = null
    ) {
        val chunks = chunkMessage(message, MAX_LOG_CHUNK_CHARS)
        for (chunk in chunks) {
            val intent = Intent(HephaistosContract.ACTION_LOG).apply {
                setPackage(HephaistosContract.LAUNCHER_PACKAGE)
                putExtra(HephaistosContract.EXTRA_SOURCE_PACKAGE, HephaistosContract.MODULE_PACKAGE)
                putExtra(HephaistosContract.EXTRA_LEVEL, level)
                putExtra(HephaistosContract.EXTRA_MESSAGE, chunk)
            }
            context.sendBroadcast(intent)

            // Si un terminal tiers autre que HEPHAISTOS écoute aussi les logs sur son propre package
            if (!targetSourcePackage.isNullOrBlank() &&
                targetSourcePackage != HephaistosContract.LAUNCHER_PACKAGE &&
                targetSourcePackage != HephaistosContract.MODULE_PACKAGE
            ) {
                val mirrorIntent = Intent(intent).apply { setPackage(targetSourcePackage) }
                context.sendBroadcast(mirrorIntent)
            }
        }
    }

    fun logInfo(message: String, targetSourcePackage: String? = null) =
        log(HephaistosContract.LOG_INFO, message, targetSourcePackage)

    fun logOut(message: String, targetSourcePackage: String? = null) =
        log(HephaistosContract.LOG_OUT, message, targetSourcePackage)

    fun logErr(message: String, targetSourcePackage: String? = null) =
        log(HephaistosContract.LOG_ERR, message, targetSourcePackage)

    /**
     * Émet l'avancement d'une tâche longue vers les notifications et l'UI de HEPHAISTOS.
     */
    fun progress(
        taskId: String,
        title: String,
        message: String,
        progress: Int,
        completed: Boolean = false,
        error: String? = null,
        canCancel: Boolean = true,
        targetSourcePackage: String? = null
    ) {
        val intent = Intent(HephaistosContract.ACTION_PROGRESS).apply {
            setPackage(HephaistosContract.LAUNCHER_PACKAGE)
            putExtra(HephaistosContract.EXTRA_SOURCE_PACKAGE, HephaistosContract.MODULE_PACKAGE)
            putExtra(HephaistosContract.EXTRA_TASK_ID, taskId)
            putExtra(HephaistosContract.EXTRA_TITLE, title)
            putExtra(HephaistosContract.EXTRA_MESSAGE, message)
            putExtra(HephaistosContract.EXTRA_PROGRESS, progress)
            putExtra(HephaistosContract.EXTRA_COMPLETED, completed)
            putExtra(HephaistosContract.EXTRA_CAN_CANCEL, canCancel)
            if (!error.isNullOrBlank()) {
                putExtra(HephaistosContract.EXTRA_ERROR, error)
            }
        }
        context.sendBroadcast(intent)

        if (!targetSourcePackage.isNullOrBlank() &&
            targetSourcePackage != HephaistosContract.LAUNCHER_PACKAGE &&
            targetSourcePackage != HephaistosContract.MODULE_PACKAGE
        ) {
            val mirror = Intent(intent).apply { setPackage(targetSourcePackage) }
            context.sendBroadcast(mirror)
        }
    }

    /**
     * Demande à HEPHAISTOS d'afficher une popup minimale déclarative.
     */
    fun showPopup(
        popupId: String,
        title: String,
        message: String,
        confirmLabel: String,
        cancelLabel: String,
        commandId: String,
        downloadUri: Uri? = null
    ) {
        downloadUri?.let {
            grantReadPermission(it, HephaistosContract.LAUNCHER_PACKAGE)
        }
        val intent = Intent(HephaistosContract.ACTION_SHOW_POPUP).apply {
            setPackage(HephaistosContract.LAUNCHER_PACKAGE)
            putExtra(HephaistosContract.EXTRA_SOURCE_PACKAGE, HephaistosContract.MODULE_PACKAGE)
            putExtra(HephaistosContract.EXTRA_POPUP_ID, popupId)
            putExtra(HephaistosContract.EXTRA_TITLE, title)
            putExtra(HephaistosContract.EXTRA_MESSAGE, message)
            putExtra(HephaistosContract.EXTRA_CONFIRM_LABEL, confirmLabel)
            putExtra(HephaistosContract.EXTRA_CANCEL_LABEL, cancelLabel)
            putExtra(HephaistosContract.EXTRA_COMMAND_ID, commandId)
            if (downloadUri != null) {
                putExtra(HephaistosContract.EXTRA_DOWNLOAD_URI, downloadUri.toString())
            }
        }
        context.sendBroadcast(intent)
    }

    /**
     * Envoie le résultat structuré JSON à la fois à SOURCE_PACKAGE (s'il est différent
     * de HEPHAISTOS) ET à HEPHAISTOS (com.hephaistos.launcher).
     */
    fun sendCommandResult(
        commandId: String,
        sourcePackage: String?,
        resultJson: JSONObject?,
        error: String? = null,
        sharedUris: List<Uri> = emptyList()
    ) {
        val targets = linkedSetOf(HephaistosContract.LAUNCHER_PACKAGE)
        if (!sourcePackage.isNullOrBlank() && sourcePackage != HephaistosContract.MODULE_PACKAGE) {
            targets.add(sourcePackage)
        }

        val payloadString = resultJson?.toString() ?: JSONObject().toString()

        for (target in targets) {
            for (uri in sharedUris) {
                grantReadPermission(uri, target)
            }
            val intent = Intent(HephaistosContract.ACTION_COMMAND_RESULT).apply {
                setPackage(target)
                putExtra(HephaistosContract.EXTRA_COMMAND_ID, commandId)
                putExtra(HephaistosContract.EXTRA_SOURCE_PACKAGE, HephaistosContract.MODULE_PACKAGE)
                putExtra(HephaistosContract.EXTRA_RESULT_JSON, payloadString)
                if (!error.isNullOrBlank()) {
                    putExtra(HephaistosContract.EXTRA_ERROR, error)
                }
            }
            context.sendBroadcast(intent)
        }
    }

    fun grantReadPermission(uri: Uri, targetPackage: String) {
        if (targetPackage.isBlank()) return
        runCatching {
            context.grantUriPermission(
                targetPackage,
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        }
    }

    companion object {
        private const val MAX_LOG_CHUNK_CHARS = 8_000

        internal fun chunkMessage(message: String, maxChars: Int = MAX_LOG_CHUNK_CHARS): List<String> {
            if (message.length <= maxChars) return listOf(message)
            val result = mutableListOf<String>()
            var start = 0
            while (start < message.length) {
                var end = (start + maxChars).coerceAtMost(message.length)
                if (end < message.length) {
                    val lastNewline = message.lastIndexOf('\n', end - 1)
                    if (lastNewline > start) {
                        end = lastNewline + 1
                    }
                }
                result.add(message.substring(start, end))
                start = end
            }
            return result
        }
    }
}

/**
 * Client utilitaire permettant à HSIGNER (ou tout module) de découvrir les autres modules
 * HEPHAISTOS installés, lire leur section "manual" JSON et leur envoyer des commandes EXECUTE.
 */
class HephaistosModuleClient(private val context: Context) {

    data class DiscoveredModule(
        val packageName: String,
        val serviceName: String,
        val manifestJson: JSONObject?
    )

    /**
     * Interroge PackageManager sur com.hephaistos.action.MODULE et lit le manifeste JSON distant.
     */
    fun discoverModules(): List<DiscoveredModule> {
        val pm = context.packageManager
        val queryIntent = Intent(HephaistosContract.ACTION_MODULE)
        val resolveInfos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentServices(
                queryIntent,
                PackageManager.ResolveInfoFlags.of(PackageManager.GET_META_DATA.toLong())
            )
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentServices(queryIntent, PackageManager.GET_META_DATA)
        }

        return resolveInfos.mapNotNull { info ->
            val serviceInfo = info.serviceInfo ?: return@mapNotNull null
            val pkg = serviceInfo.packageName
            val manifestResId = serviceInfo.metaData?.getInt(HephaistosContract.META_DATA_MANIFEST) ?: 0
            val manifestJson = if (manifestResId != 0) {
                runCatching {
                    val remoteRes = pm.getResourcesForApplication(pkg)
                    remoteRes.openRawResource(manifestResId).bufferedReader(Charsets.UTF_8).use {
                        JSONObject(it.readText())
                    }
                }.getOrNull()
            } else {
                null
            }
            DiscoveredModule(
                packageName = pkg,
                serviceName = serviceInfo.name,
                manifestJson = manifestJson
            )
        }
    }

    /**
     * Lit la section "manual" d'un module cible com.hephaistos.*.
     */
    fun readModuleManual(targetPackage: String): JSONObject? {
        return discoverModules()
            .firstOrNull { it.packageName == targetPackage }
            ?.manifestJson
            ?.optJSONObject("manual")
    }

    /**
     * Envoie une commande com.hephaistos.action.EXECUTE à un autre module satellite HEPHAISTOS.
     */
    fun executeModuleCommand(
        targetPackage: String,
        commandId: String,
        params: JSONObject = JSONObject(),
        serviceClassName: String? = null
    ): Boolean {
        val targetService = serviceClassName ?: discoverModules()
            .firstOrNull { it.packageName == targetPackage }
            ?.serviceName

        val intent = Intent(HephaistosContract.ACTION_EXECUTE).apply {
            if (!targetService.isNullOrBlank()) {
                component = ComponentName(targetPackage, targetService)
            } else {
                setPackage(targetPackage)
            }
            putExtra(HephaistosContract.EXTRA_COMMAND_ID, commandId)
            putExtra(HephaistosContract.EXTRA_PARAMS_JSON, params.toString())
            putExtra(HephaistosContract.EXTRA_SOURCE_PACKAGE, HephaistosContract.MODULE_PACKAGE)
        }

        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            true
        }.getOrElse {
            runCatching {
                context.startService(intent)
                true
            }.getOrDefault(false)
        }
    }
}
