package com.hephaistos.hsigner

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import com.hephaistos.hsigner.protocol.HephaistosContract

/**
 * Passerelle optionnelle permettant aux terminaux ou scripts (ex. am broadcast)
 * de déclencher ModuleEngineService même s'ils utilisent sendBroadcast au lieu de startService.
 */
class ModuleBroadcastCommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != HephaistosContract.ACTION_EXECUTE_BROADCAST) return
        val serviceIntent = Intent(context, ModuleEngineService::class.java).apply {
            action = HephaistosContract.ACTION_EXECUTE
            putExtras(intent)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
}
