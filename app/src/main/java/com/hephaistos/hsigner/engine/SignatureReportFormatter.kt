package com.hephaistos.hsigner.engine

import org.json.JSONArray
import org.json.JSONObject

/**
 * Formate les résultats de vérification HSIGNER :
 * 1) Rapport texte terminal français exact avec tous les détails cryptographiques.
 * 2) Payload JSON structuré complet pour HEPHAISTOS, terminaux et modules IA.
 */
object SignatureReportFormatter {

    fun formatTerminalReport(report: ApkVerificationReport): String {
        val sb = StringBuilder()
        val meta = report.metadata

        val versionDisplay = buildString {
            if (meta.versionName.isNotBlank() && meta.versionName != "?") {
                val vPrefix = if (meta.versionName.startsWith("v", ignoreCase = true)) {
                    meta.versionName
                } else {
                    "v${meta.versionName}"
                }
                append(vPrefix)
            }
            if (meta.versionCode > 0L) {
                if (isNotEmpty()) append(" ")
                append("(${meta.versionCode})")
            }
        }.trim()

        sb.appendLine(
            buildString {
                append("Vérification de la signature: ")
                append(meta.appName)
                if (versionDisplay.isNotEmpty()) {
                    append(" ").append(versionDisplay)
                }
            }
        )
        sb.appendLine("Chemin: ${meta.displayPath}")
        sb.appendLine()
        sb.appendLine("Schéma de signature : ${report.schemeSummary}")
        sb.appendLine()

        if (report.certificates.isEmpty()) {
            sb.appendLine("AUCUN CERTIFICAT TROUVÉ : cet APK ne contient pas de signature X.509 exploitable.")
        } else {
            for ((idx, cert) in report.certificates.withIndex()) {
                sb.appendLine("CERTIFICAT №${cert.index}")
                sb.appendLine("Type de certificat : ${cert.certificateType}")
                sb.appendLine("Version du certificat : ${cert.version}")
                sb.appendLine("Numéros de série: ${cert.serialNumberDecimal}")
                sb.appendLine("Propriétaire du certificat : ${cert.subjectDn}")
                val issuerText = if (cert.isSelfSigned) {
                    "Auto-signé par le propriétaire du certificat"
                } else {
                    cert.issuerDn
                }
                sb.appendLine("Émetteur de certificat : $issuerText")
                sb.appendLine("Validité : de ${cert.validFromFormatted} à ${cert.validToFormatted}")
                sb.appendLine("Algorithme de signature : ${cert.signatureAlgorithm}")
                sb.appendLine()
                sb.appendLine("Code de hachage : ${cert.hashCodeHex} (${cert.hashCodeInt})")
                sb.appendLine("Signature CRC32 : ${cert.crc32Hex} (${cert.crc32Decimal})")
                sb.appendLine("Signature MD5 : ${cert.md5Hex}")
                sb.appendLine("Signature SHA-1 : ${cert.sha1Hex}")
                sb.appendLine("Signature SHA-224 : ${cert.sha224Hex}")
                sb.appendLine("Signature SHA-256 : ${cert.sha256Hex}")
                sb.appendLine("Signature SHA-384 : ${cert.sha384Hex}")
                sb.appendLine("Signature SHA-512 : ${cert.sha512Hex}")
                sb.appendLine()
                sb.appendLine("Base64 du certificat : ${cert.certificateBase64}")
                sb.appendLine()
                sb.appendLine("Bits de signature : ${cert.signatureBitsHex}")
                sb.appendLine()
                sb.appendLine("Clé publique : ${cert.publicKeyFormatted}")
                sb.appendLine()
                sb.appendLine("Base64 de signature : ${cert.signatureBase64}")
                if (idx < report.certificates.lastIndex) {
                    sb.appendLine()
                }
            }
        }

        // Section d'audit technique avancé (statut cryptographique V1-V4, rotation, SourceStamp, erreurs)
        sb.appendLine()
        sb.appendLine("─── AUDIT TECHNIQUE V1 / V2 / V3 / V3.1 / V4 ───")
        sb.appendLine("Statut global : ${if (report.isVerified) "VALIDE (Signature intègre)" else "INVALIDE / NON VÉRIFIÉ"}")
        sb.appendLine("Package : ${meta.packageName} | Taille : ${meta.fileSizeBytes} octets" +
            buildString {
                meta.minSdkVersion?.let { append(" | minSdk=$it") }
                meta.targetSdkVersion?.let { append(" | targetSdk=$it") }
            }
        )
        for (scheme in report.schemeDetails) {
            val state = if (scheme.verified) "VÉRIFIÉ" else "ÉCHEC / NON VÉRIFIÉ"
            val sdkRange = if (scheme.minSdkVersion != null || scheme.maxSdkVersion != null) {
                " [SDK ${scheme.minSdkVersion ?: "?"}..${scheme.maxSdkVersion ?: "∞"}]"
            } else ""
            val companion = scheme.companionPath?.let { " (idsig: $it)" } ?: ""
            sb.appendLine("• ${scheme.schemeName} : $state — ${scheme.signerCount} signataire(s)$sdkRange$companion")
            scheme.errors.forEach { sb.appendLine("   [ERREUR ${scheme.schemeName}] $it") }
            scheme.warnings.forEach { sb.appendLine("   [AVERTISSEMENT ${scheme.schemeName}] $it") }
        }
        if (report.v3Lineage.isNotEmpty()) {
            sb.appendLine("• Lignage de rotation de clés V3 (${report.v3Lineage.size} maillon(s)) :")
            report.v3Lineage.forEach { node ->
                sb.appendLine("   #${node.index} ${node.subjectDn} (SHA-256: ${node.sha256})")
            }
        }
        if (report.sourceStampPresent) {
            sb.appendLine("• SourceStamp : ${if (report.sourceStampVerified) "VÉRIFIÉ" else "PRÉSENT (Non vérifié)"}${report.sourceStampSubject?.let { " — $it" } ?: ""}")
        }
        if (report.globalErrors.isNotEmpty()) {
            sb.appendLine("Erreurs globales :")
            report.globalErrors.forEach { sb.appendLine("  - $it") }
        }
        if (report.globalWarnings.isNotEmpty()) {
            sb.appendLine("Avertissements globaux :")
            report.globalWarnings.forEach { sb.appendLine("  - $it") }
        }

        return sb.toString().trimEnd()
    }

    fun toJson(report: ApkVerificationReport, includeTerminalText: Boolean = true): JSONObject {
        val meta = report.metadata
        return JSONObject().apply {
            put("app_name", meta.appName)
            put("package_name", meta.packageName)
            put("version_name", meta.versionName)
            put("version_code", meta.versionCode)
            meta.minSdkVersion?.let { put("min_sdk_version", it) }
            meta.targetSdkVersion?.let { put("target_sdk_version", it) }
            put("path", meta.displayPath)
            put("file_size_bytes", meta.fileSizeBytes)
            put("verified", report.isVerified)
            put("scheme_summary", report.schemeSummary)
            put("detected_schemes", JSONArray(report.detectedSchemes))
            put("verified_schemes", JSONArray(report.verifiedSchemes))
            put("source_stamp_present", report.sourceStampPresent)
            put("source_stamp_verified", report.sourceStampVerified)
            report.sourceStampSubject?.let { put("source_stamp_subject", it) }

            put("schemes", JSONArray().apply {
                report.schemeDetails.forEach { s ->
                    put(JSONObject().apply {
                        put("scheme", s.schemeName)
                        put("present", s.present)
                        put("verified", s.verified)
                        put("signer_count", s.signerCount)
                        put("algorithms", JSONArray(s.algorithms))
                        s.minSdkVersion?.let { put("min_sdk_version", it) }
                        s.maxSdkVersion?.let { put("max_sdk_version", it) }
                        s.rotationMinSdkVersion?.let { put("rotation_min_sdk_version", it) }
                        s.companionPath?.let { put("companion_path", it) }
                        put("errors", JSONArray(s.errors))
                        put("warnings", JSONArray(s.warnings))
                    })
                }
            })

            put("v3_lineage", JSONArray().apply {
                report.v3Lineage.forEach { n ->
                    put(JSONObject().apply {
                        put("index", n.index)
                        put("subject_dn", n.subjectDn)
                        put("sha256", n.sha256)
                    })
                }
            })

            put("certificates", JSONArray().apply {
                report.certificates.forEach { c ->
                    put(JSONObject().apply {
                        put("index", c.index)
                        put("type", c.certificateType)
                        put("version", c.version)
                        put("serial_number_decimal", c.serialNumberDecimal)
                        put("serial_number_hex", c.serialNumberHex)
                        put("subject_dn", c.subjectDn)
                        put("issuer_dn", c.issuerDn)
                        put("self_signed", c.isSelfSigned)
                        put("valid_from_epoch_ms", c.validFromEpochMs)
                        put("valid_to_epoch_ms", c.validToEpochMs)
                        put("valid_from", c.validFromFormatted)
                        put("valid_to", c.validToFormatted)
                        put("signature_algorithm", c.signatureAlgorithm)
                        put("hash_code_hex", c.hashCodeHex)
                        put("hash_code_int", c.hashCodeInt)
                        put("crc32_hex", c.crc32Hex)
                        put("crc32_decimal", c.crc32Decimal)
                        put("md5", c.md5Hex)
                        put("sha1", c.sha1Hex)
                        put("sha224", c.sha224Hex)
                        put("sha256", c.sha256Hex)
                        put("sha384", c.sha384Hex)
                        put("sha512", c.sha512Hex)
                        put("certificate_base64", c.certificateBase64)
                        put("signature_bits_hex", c.signatureBitsHex)
                        put("public_key", c.publicKeyFormatted)
                        put("public_key_algorithm", c.publicKeyAlgorithm)
                        c.publicKeySizeBits?.let { put("public_key_size_bits", it) }
                        put("signature_base64", c.signatureBase64)
                        c.rawCryptographicSignatureBase64?.let { put("raw_pkcs7_or_v4_signature_base64", it) }
                        put("source_schemes", JSONArray(c.sourceSchemes))
                    })
                }
            })

            put("errors", JSONArray(report.globalErrors))
            put("warnings", JSONArray(report.globalWarnings))
            if (includeTerminalText) {
                put("terminal_report", formatTerminalReport(report))
            }
        }
    }
}
