package com.hephaistos.hsigner

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import com.hephaistos.hsigner.engine.HsignerCommandProcessor
import com.hephaistos.hsigner.engine.ReadmeDocumentGenerator
import com.hephaistos.hsigner.protocol.HephaistosContract
import java.io.File
import java.io.FileNotFoundException

/**
 * ContentProvider exporté (com.hephaistos.hsigner.provider) offrant :
 * - openFile() pour télécharger directement HSIGNER_README.md (/readme), /manifest ou /spec
 * - call() pour exécuter de façon synchrone verify_apk, get_readme ou inspect_capabilities
 * - query() pour découvrir les URI de documentation disponibles
 */
class HsignerContentProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val cursor = MatrixCursor(arrayOf("module", "version", "readme_uri", "manifest_uri", "provider_authority"))
        cursor.addRow(
            arrayOf(
                HephaistosContract.MODULE_PACKAGE,
                "1.0.0",
                "content://${HephaistosContract.CONTENT_PROVIDER_AUTHORITY}/readme",
                "content://${HephaistosContract.CONTENT_PROVIDER_AUTHORITY}/manifest",
                HephaistosContract.CONTENT_PROVIDER_AUTHORITY
            )
        )
        return cursor
    }

    override fun getType(uri: Uri): String {
        return when (uri.lastPathSegment) {
            "readme" -> "text/markdown"
            "manifest", "spec" -> "application/json"
            else -> "application/octet-stream"
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (!mode.contains("r")) throw SecurityException("Lecture seule autorisée sur ce fournisseur")
        val ctx = context ?: throw FileNotFoundException("Contexte indisponible")
        val processor = HsignerCommandProcessor(ctx)
        val rawManifest = processor.readRawManifestString()

        val targetFile: File = when (uri.lastPathSegment) {
            "readme", ReadmeDocumentGenerator.README_FILENAME -> {
                processor.writePersistentDoc(
                    ReadmeDocumentGenerator.README_FILENAME,
                    ReadmeDocumentGenerator.buildMarkdownReadme(rawManifest)
                )
            }
            "manifest", "spec", ReadmeDocumentGenerator.SPEC_FILENAME -> {
                processor.writePersistentDoc(ReadmeDocumentGenerator.SPEC_FILENAME, rawManifest)
            }
            else -> throw FileNotFoundException("Ressource inconnue : $uri")
        }
        return ParcelFileDescriptor.open(targetFile, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val ctx = context ?: return Bundle().apply {
            putString(HephaistosContract.EXTRA_ERROR, "Contexte fournisseur indisponible")
        }
        val processor = HsignerCommandProcessor(ctx)
        val paramsJson = extras?.getString(HephaistosContract.EXTRA_PARAMS_JSON) ?: arg
        val sourcePackage = extras?.getString(HephaistosContract.EXTRA_SOURCE_PACKAGE)
        val emitBroadcasts = extras?.getBoolean("emit_broadcasts", false) ?: false

        val result = runCatching {
            processor.executeCommand(
                commandId = method,
                paramsJsonRaw = paramsJson,
                sourcePackage = sourcePackage,
                emitBroadcasts = emitBroadcasts
            )
        }

        return Bundle().apply {
            result.onSuccess { json ->
                putString(HephaistosContract.EXTRA_COMMAND_ID, method)
                putString(HephaistosContract.EXTRA_RESULT_JSON, json.toString())
            }.onFailure { err ->
                putString(HephaistosContract.EXTRA_COMMAND_ID, method)
                putString(HephaistosContract.EXTRA_ERROR, err.message ?: err.javaClass.simpleName)
            }
        }
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
