package com.hephaistos.hsigner

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import androidx.test.core.app.ApplicationProvider
import com.hephaistos.hsigner.engine.HsignerCommandProcessor
import com.hephaistos.hsigner.protocol.HephaistosContract
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HsignerProtocolRobolectricTest {

    @Test
    fun `application has zero launcher activities and exposes Hephaistos service`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val pm = context.packageManager

        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).setPackage(context.packageName)
        val launcherMatches = pm.queryIntentActivities(launcherIntent, 0)
        assertTrue("HSIGNER must have ZERO launcher activities", launcherMatches.isEmpty())

        val moduleIntent = Intent(HephaistosContract.ACTION_MODULE).setPackage(context.packageName)
        val moduleServices = pm.queryIntentServices(moduleIntent, PackageManager.GET_META_DATA)
        assertEquals(1, moduleServices.size)

        val metaData = moduleServices.first().serviceInfo.metaData
        assertNotNull(metaData)
        assertTrue(metaData.getInt(HephaistosContract.META_DATA_MANIFEST) != 0)
    }

    @Test
    fun `hephaistos_manifest json satisfies all UI and manual checklist rules`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val raw = context.resources.openRawResource(R.raw.hephaistos_manifest).bufferedReader().use { it.readText() }
        val manifest = JSONObject(raw)

        assertEquals("shield", manifest.getString("icon"))
        val ui = manifest.getJSONObject("ui")
        val elements = ui.getJSONArray("elements")
        val popups = ui.getJSONArray("popups")
        val manual = manifest.getJSONObject("manual")
        assertEquals("1.0", manual.getString("protocol_version"))
        assertEquals(HephaistosContract.ACTION_EXECUTE, manual.getString("target_action"))
        assertEquals(HephaistosContract.ACTION_COMMAND_RESULT, manual.getString("callback_action"))

        val manualCommandIds = mutableSetOf<String>()
        val commands = manual.getJSONArray("commands")
        for (i in 0 until commands.length()) {
            manualCommandIds.add(commands.getJSONObject(i).getString("id"))
        }

        var hasFilePicker = false
        var hasVerifyBtn = false
        var hasReadmeBtn = false

        for (i in 0 until elements.length()) {
            val el = elements.getJSONObject(i)
            val type = el.getString("type")
            if (type == "file_picker") {
                hasFilePicker = true
                assertFalse(el.optString("title").isBlank())
            }
            if (type == "action_button") {
                val cmdId = el.getString("command_id")
                assertTrue("UI command_id '$cmdId' must be documented in manual.commands", manualCommandIds.contains(cmdId))
                if (el.optString("title") == "Verify" || el.optString("label") == "Verify") hasVerifyBtn = true
                if (el.optString("title") == "Readme" || el.optString("label") == "Readme") hasReadmeBtn = true
            }
        }
        for (i in 0 until popups.length()) {
            val cmdId = popups.getJSONObject(i).getString("command_id")
            assertTrue("Popup command_id '$cmdId' must be documented in manual.commands", manualCommandIds.contains(cmdId))
        }

        assertTrue(hasFilePicker)
        assertTrue(hasVerifyBtn)
        assertTrue(hasReadmeBtn)

        val decoded = com.hephaistos.hsigner.engine.ApkInputResolver.decodeSafDocumentPath(
            Uri.parse("content://com.android.externalstorage.documents/document/primary%3ARecordings%2FStorageManager%2FStorageManager.apk")
        )
        assertEquals("/storage/emulated/0/Recordings/StorageManager/StorageManager.apk", decoded)
    }

    @Test
    fun `get_readme and inspect_capabilities return complete documentation and downloadable URI`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val processor = HsignerCommandProcessor(context)

        val readmeRes = processor.executeCommand(
            commandId = HephaistosContract.CMD_GET_README,
            paramsJsonRaw = """{"format":"both","open_popup":false}""",
            sourcePackage = "com.hephaistos.terminal",
            emitBroadcasts = false
        )
        assertEquals("success", readmeRes.getString("status"))
        assertTrue(readmeRes.getString("readme_markdown").contains("com.hephaistos.action.EXECUTE"))
        assertTrue(readmeRes.getString("readme_uri").startsWith("content://com.hephaistos.hsigner.fileprovider/"))

        val capRes = processor.executeCommand(
            commandId = HephaistosContract.CMD_INSPECT_CAPABILITIES,
            paramsJsonRaw = "{}",
            sourcePackage = "com.hephaistos.launcher",
            emitBroadcasts = false
        )
        assertEquals("success", capRes.getString("status"))
        assertEquals(5, capRes.getJSONArray("supported_schemes").length())

        val provider = HsignerContentProvider()
        val cursor = provider.query(Uri.parse("content://${HephaistosContract.CONTENT_PROVIDER_AUTHORITY}/info"), null, null, null, null)
        assertTrue(cursor.moveToFirst())
        assertEquals(HephaistosContract.MODULE_PACKAGE, cursor.getString(0))
        cursor.close()

        val errRes = processor.executeCommand(
            commandId = HephaistosContract.CMD_VERIFY_APK,
            paramsJsonRaw = """{"apk_uris":[]}""",
            sourcePackage = "com.hephaistos.launcher",
            emitBroadcasts = false
        )
        assertEquals("error", errRes.getString("status"))
        assertFalse(errRes.optString("error").isBlank())
    }
}
