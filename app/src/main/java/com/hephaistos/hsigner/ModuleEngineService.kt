package com.hephaistos.hsigner

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.hephaistos.hsigner.engine.HsignerCommandProcessor
import com.hephaistos.hsigner.protocol.HephaistosBridge
import com.hephaistos.hsigner.protocol.HephaistosContract
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Service moteur headless principal découvert par HEPHAISTOS via com.hephaistos.action.MODULE
 * et commandé via com.hephaistos.action.EXECUTE.
 */
class ModuleEngineService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var bridge: HephaistosBridge
    private lateinit var processor: HsignerCommandProcessor

    override fun onCreate() {
        super.onCreate()
        bridge = HephaistosBridge(applicationContext)
        processor = HsignerCommandProcessor(applicationContext, bridge)
        ensureNotificationChannel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelfIfIdle(startId)
            return START_NOT_STICKY
        }

        val action = intent.action
        if (action == HephaistosContract.ACTION_CANCEL_TASK) {
            val targetTaskId = intent.getStringExtra(HephaistosContract.EXTRA_TASK_ID)
            cancelTask(targetTaskId)
            stopSelfIfIdle(startId)
            return START_NOT_STICKY
        }

        val commandId = intent.getStringExtra(HephaistosContract.EXTRA_COMMAND_ID)
        val paramsJson = intent.getStringExtra(HephaistosContract.EXTRA_PARAMS_JSON)
        val sourcePackage = intent.getStringExtra(HephaistosContract.EXTRA_SOURCE_PACKAGE)
        val taskId = intent.getStringExtra(HephaistosContract.EXTRA_TASK_ID) ?: UUID.randomUUID().toString()

        if (commandId.isNullOrBlank()) {
            // Simple ping / découverte sans commande
            stopSelfIfIdle(startId)
            return START_NOT_STICKY
        }

        promoteToForeground()

        val cancelledFlag = AtomicBoolean(false)
        lateinit var job: Job
        job = serviceScope.launch {
            try {
                processor.executeCommand(
                    commandId = commandId,
                    paramsJsonRaw = paramsJson,
                    sourcePackage = sourcePackage,
                    taskId = taskId,
                    isCancelled = { cancelledFlag.get() },
                    emitBroadcasts = true
                )
            } catch (t: Throwable) {
                val errMsg = "Erreur interne HSIGNER : ${t.message ?: t.javaClass.simpleName}"
                bridge.logErr(errMsg, sourcePackage)
                bridge.progress(
                    taskId = taskId,
                    title = "HSIGNER — Erreur",
                    message = errMsg,
                    progress = 100,
                    completed = true,
                    error = errMsg,
                    canCancel = false,
                    targetSourcePackage = sourcePackage
                )
                bridge.sendCommandResult(commandId, sourcePackage, null, errMsg)
            } finally {
                activeTasks.remove(taskId)
                stopSelfIfIdle(startId)
            }
        }
        activeTasks[taskId] = TaskEntry(job, cancelledFlag)

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    private fun promoteToForeground() {
        val notification = buildNotification()
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        }
    }

    private fun stopSelfIfIdle(startId: Int) {
        if (activeTasks.isEmpty()) {
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
            }
            stopSelf(startId)
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = getString(R.string.notification_channel_description)
                }
                nm.createNotificationChannel(channel)
            }
        }
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(getString(R.string.notification_verifying_title))
            .setContentText(getString(R.string.notification_verifying_text))
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "hsigner_engine_channel"
        private const val NOTIFICATION_ID = 4109

        private data class TaskEntry(val job: Job, val cancelled: AtomicBoolean)
        private val activeTasks = ConcurrentHashMap<String, TaskEntry>()

        fun cancelTask(taskId: String?) {
            if (taskId.isNullOrBlank()) {
                activeTasks.values.forEach { entry ->
                    entry.cancelled.set(true)
                }
            } else {
                activeTasks[taskId]?.cancelled?.set(true)
            }
        }
    }
}
