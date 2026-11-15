package com.hephaistos.hsigner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.hephaistos.hsigner.protocol.HephaistosContract

/**
 * Récepteur officiel pour com.hephaistos.action.CANCEL_TASK permettant d'interrompre
 * une vérification multi-APK en cours.
 */
class ModuleCancelReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == HephaistosContract.ACTION_CANCEL_TASK) {
            val taskId = intent.getStringExtra(HephaistosContract.EXTRA_TASK_ID)
            ModuleEngineService.cancelTask(taskId)
        }
    }
}
