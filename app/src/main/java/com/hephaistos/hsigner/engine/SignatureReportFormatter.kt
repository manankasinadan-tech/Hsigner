package com.hephaistos.hsigner.engine

import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * Formate les résultats de vérification HSIGNER :
 * 1) Rapport texte terminal français ultra-complet préservant intégralement le format de référence
 *    enrichi avec l'audit X.509 avancé, les empreintes Console/SPKI, l'intégrité du fichier APK,
 *    le profil de sécurité du manifeste, les blocs V1-V4 et le score de confiance.
 * 2) Payload JSON structuré complet pour HEPHAISTOS, terminaux et modules IA.
 */
object SignatureReportFormatter {

    fun formatTerminalReport(
        report: ApkVerificationReport,
        detailLevel: String = "ultra_complet"
    ): String {
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
                if (detailLevel != "compact") {
                    sb.appendLine()
                    sb.appendLine("Base64 du certificat : ${cert.certificateBase64}")
                    sb.appendLine()
                    sb.appendLine("Bits de signature : ${cert.signatureBitsHex}")
                    sb.appendLine()
                    sb.appendLine("Clé publique : ${cert.publicKeyFormatted}")
                    sb.appendLine()
                    sb.appendLine("Base64 de signature : ${cert.signatureBase64}")
                } else {
                    sb.appendLine("Clé publique : ${cert.publicKeyFormatted}")
                }
                if (idx < report.certificates.lastIndex) {
                    sb.appendLine()
                }
            }
        }

        if (detailLevel == "ultra_complet" && report.certificates.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("─── PROPRIÉTÉS X.509 AVANCÉES & EMPREINTES CONSOLE ───")
            for (cert in report.certificates) {
                sb.appendLine("CERTIFICAT №${cert.index} — Détails avancés :")
                sb.appendLine("• Statut temporel : ${cert.validityStatusLabel} (durée totale : ${cert.validityDurationDays} jours)")
                sb.appendLine("• Numéro de série (Hex) : ${cert.serialNumberHex}")
                sb.appendLine("• Clé publique : ${cert.publicKeyAlgorithm} ${cert.publicKeySizeBits?.let { "$it bits" } ?: ""}".trim())
                sb.appendLine("• Schémas associés : ${if (cert.sourceSchemes.isNotEmpty()) cert.sourceSchemes.joinToString(", ") else "Général"}")
                sb.appendLine("• SHA-1 (Play/Firebase) : ${cert.sha1ColonUpper}")
                sb.appendLine("• SHA-256 (Play/Firebase) : ${cert.sha256ColonUpper}")
                sb.appendLine("• Pin SPKI SHA-256 (Base64) : sha256/${cert.spkiSha256Base64}")
                sb.appendLine("• Pin SPKI SHA-256 (Hex) : ${cert.spkiSha256Hex}")
                if (cert.subjectComponents.isNotEmpty()) {
                    val dnSummary = cert.subjectComponents.entries.joinToString(" | ") { "${it.key}=${it.value}" }
                    sb.appendLine("• Identité DN décomposée : $dnSummary")
                }
                cert.basicConstraintsSummary?.let { sb.appendLine("• Contraintes de base : $it") }
                if (cert.keyUsageList.isNotEmpty()) {
                    sb.appendLine("• KeyUsage : ${cert.keyUsageList.joinToString(", ")}")
                }
                if (cert.extendedKeyUsageList.isNotEmpty()) {
                    sb.appendLine("• ExtendedKeyUsage : ${cert.extendedKeyUsageList.joinToString(", ")}")
                }
                cert.subjectKeyIdentifierHex?.let { sb.appendLine("• SubjectKeyIdentifier (SKI) : $it") }
                cert.authorityKeyIdentifierHex?.let { sb.appendLine("• AuthorityKeyIdentifier (AKI) : $it") }
                if (cert.extensionOidsSummary.isNotEmpty()) {
                    sb.appendLine("• Extensions X.509 (${cert.extensionOidsSummary.size}) : ${cert.extensionOidsSummary.joinToString("; ")}")
                }
                cert.rawCryptographicSignatureBase64?.let {
                    sb.appendLine("• Signature PKCS#7 / V4 brute (Base64, ${it.length} car.) : ${it.take(96)}${if (it.length > 96) "…" else ""}")
                }
                cert.cryptographicWarnings.forEach { warn ->
                    sb.appendLine("  [ALERTE CRYPTO] $warn")
                }
            }
        }

        // Empreintes & structure du fichier APK complet
        report.fileForensics?.let { f ->
            val sizeMb = String.format(Locale.FRANCE, "%.2f Mo", f.fileSizeBytes / (1024.0 * 1024.0))
            sb.appendLine()
            sb.appendLine("─── EMPREINTES & STRUCTURE DU FICHIER APK ───")
            sb.appendLine("Taille du fichier : ${f.fileSizeBytes} octets ($sizeMb)")
            sb.appendLine("APK CRC32 : ${f.crc32Hex}")
            sb.appendLine("APK MD5 : ${f.md5Hex}")
            sb.appendLine("APK SHA-1 : ${f.sha1Hex}")
            sb.appendLine("APK SHA-256 : ${f.sha256Hex}")
            sb.appendLine("APK SHA-512 : ${f.sha512Hex}")
            sb.appendLine("Archive ZIP : ${f.totalZipEntries} entrée(s) | ${f.dexCount} fichier(s) DEX | resources.arsc=${if (f.hasResourcesArsc) "Oui" else "Non"} | Kotlin=${if (f.hasKotlinMetadata) "Oui" else "Non"}")
            val abiText = if (f.nativeAbis.isEmpty()) "Aucune (Pure Dalvik/ART)" else "${f.nativeAbis.joinToString(", ")} (${f.nativeLibrariesCount} lib .so)"
            sb.appendLine("Bibliothèques natives (ABI) : $abiText")
        }

        // Manifeste & profil sécurité
        sb.appendLine()
        sb.appendLine("─── MANIFESTE & PROFIL SÉCURITÉ APK ───")
        sb.appendLine(
            "Package : ${meta.packageName}" +
                buildString {
                    meta.minSdkVersion?.let { append(" | minSdk=$it") }
                    meta.targetSdkVersion?.let { append(" | targetSdk=$it") }
                    meta.compileSdkVersion?.let { append(" | compileSdk=$it") }
                }
        )
        if (meta.debuggable != null || meta.allowBackup != null || meta.usesCleartextTraffic != null || meta.testOnly != null) {
            sb.appendLine(
                "Flags sécurité : debuggable=${meta.debuggable ?: "non défini(false)"} | " +
                    "allowBackup=${meta.allowBackup ?: "défaut(true)"} | " +
                    "cleartextTraffic=${meta.usesCleartextTraffic ?: "défaut"} | " +
                    "testOnly=${meta.testOnly ?: false}"
            )
        }
        if (meta.permissions.isNotEmpty()) {
            sb.appendLine("Permissions déclarées (${meta.permissions.size}) : ${meta.permissions.joinToString(", ")}")
        }

        // Audit technique V1-V4 & APK Signing Block
        sb.appendLine()
        sb.appendLine("─── AUDIT TECHNIQUE V1 / V2 / V3 / V3.1 / V4 ───")
        sb.appendLine("Statut global : ${if (report.isVerified) "VALIDE (Signature intègre)" else "INVALIDE / NON VÉRIFIÉ"}")
        report.signingBlockSizeBytes?.let { blockSize ->
            sb.appendLine("APK Signing Block 42 : $blockSize octets | Blocs (${report.signingBlockIdsNamed.size}) : ${report.signingBlockIdsNamed.joinToString(", ")}")
        }
        for (scheme in report.schemeDetails) {
            val state = if (scheme.verified) "VÉRIFIÉ" else "ÉCHEC / NON VÉRIFIÉ"
            val sdkRange = if (scheme.minSdkVersion != null || scheme.maxSdkVersion != null) {
                " [SDK ${scheme.minSdkVersion ?: "?"}..${scheme.maxSdkVersion ?: "∞"}]"
            } else ""
            val companion = scheme.companionPath?.let { " (idsig: $it)" } ?: ""
            sb.appendLine("• ${scheme.schemeName} : $state — ${scheme.signerCount} signataire(s)$sdkRange$companion")
            if (scheme.algorithms.isNotEmpty()) {
                sb.appendLine("   Entrées JAR : ${scheme.algorithms.joinToString(", ")}")
            }
            if (scheme.contentDigests.isNotEmpty()) {
                sb.appendLine("   Algorithmes / Condensats : ${scheme.contentDigests.joinToString(" | ")}")
            }
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

        if (report.securityRating.isNotBlank() || report.securityAssessments.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("─── SYNTHÈSE & NIVEAU DE CONFIANCE ───")
            if (report.securityRating.isNotBlank()) {
                sb.appendLine("Niveau de confiance : ${report.securityRating}")
            }
            report.securityAssessments.forEach { sb.appendLine("• $it") }
        }

        return sb.toString().trimEnd()
    }

    fun toJson(
        report: ApkVerificationReport,
        includeTerminalText: Boolean = true,
        detailLevel: String = "ultra_complet"
    ): JSONObject {
        val meta = report.metadata
        return JSONObject().apply {
            put("app_name", meta.appName)
            put("package_name", meta.packageName)
            put("version_name", meta.versionName)
            put("version_code", meta.versionCode)
            meta.minSdkVersion?.let { put("min_sdk_version", it) }
            meta.targetSdkVersion?.let { put("target_sdk_version", it) }
            meta.compileSdkVersion?.let { put("compile_sdk_version", it) }
            meta.debuggable?.let { put("debuggable", it) }
            meta.allowBackup?.let { put("allow_backup", it) }
            meta.usesCleartextTraffic?.let { put("uses_cleartext_traffic", it) }
            meta.testOnly?.let { put("test_only", it) }
            put("permissions", JSONArray(meta.permissions))
            put("path", meta.displayPath)
            put("file_size_bytes", meta.fileSizeBytes)
            put("verified", report.isVerified)
            put("scheme_summary", report.schemeSummary)
            put("security_rating", report.securityRating)
            put("security_assessments", JSONArray(report.securityAssessments))
            put("detected_schemes", JSONArray(report.detectedSchemes))
            put("verified_schemes", JSONArray(report.verifiedSchemes))
            put("source_stamp_present", report.sourceStampPresent)
            put("source_stamp_verified", report.sourceStampVerified)
            report.sourceStampSubject?.let { put("source_stamp_subject", it) }
            report.signingBlockSizeBytes?.let { put("signing_block_size_bytes", it) }
            put("signing_block_ids", JSONArray(report.signingBlockIdsNamed))

            report.fileForensics?.let { f ->
                put("apk_file_forensics", JSONObject().apply {
                    put("file_size_bytes", f.fileSizeBytes)
                    put("crc32", f.crc32Hex)
                    put("md5", f.md5Hex)
                    put("sha1", f.sha1Hex)
                    put("sha256", f.sha256Hex)
                    put("sha512", f.sha512Hex)
                    put("total_zip_entries", f.totalZipEntries)
                    put("dex_count", f.dexCount)
                    put("native_libraries_count", f.nativeLibrariesCount)
                    put("native_abis", JSONArray(f.nativeAbis))
                    put("has_resources_arsc", f.hasResourcesArsc)
                    put("has_kotlin_metadata", f.hasKotlinMetadata)
                })
            }

            put("schemes", JSONArray().apply {
                report.schemeDetails.forEach { s ->
                    put(JSONObject().apply {
                        put("scheme", s.schemeName)
                        put("present", s.present)
                        put("verified", s.verified)
                        put("signer_count", s.signerCount)
                        put("algorithms", JSONArray(s.algorithms))
                        put("content_digests", JSONArray(s.contentDigests))
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
                        put("subject_components", JSONObject(c.subjectComponents))
                        put("issuer_dn", c.issuerDn)
                        put("self_signed", c.isSelfSigned)
                        put("valid_from_epoch_ms", c.validFromEpochMs)
                        put("valid_to_epoch_ms", c.validToEpochMs)
                        put("valid_from", c.validFromFormatted)
                        put("valid_to", c.validToFormatted)
                        put("validity_status", c.validityStatusLabel)
                        put("validity_duration_days", c.validityDurationDays)
                        put("currently_valid", c.isCurrentlyValid)
                        put("is_debug_certificate", c.isDebugCertificate)
                        put("signature_algorithm", c.signatureAlgorithm)
                        put("hash_code_hex", c.hashCodeHex)
                        put("hash_code_int", c.hashCodeInt)
                        put("crc32_hex", c.crc32Hex)
                        put("crc32_decimal", c.crc32Decimal)
                        put("md5", c.md5Hex)
                        put("sha1", c.sha1Hex)
                        put("sha1_colon_upper", c.sha1ColonUpper)
                        put("sha224", c.sha224Hex)
                        put("sha256", c.sha256Hex)
                        put("sha256_colon_upper", c.sha256ColonUpper)
                        put("sha384", c.sha384Hex)
                        put("sha512", c.sha512Hex)
                        put("spki_sha256_hex", c.spkiSha256Hex)
                        put("spki_sha256_base64", c.spkiSha256Base64)
                        put("certificate_base64", c.certificateBase64)
                        put("signature_bits_hex", c.signatureBitsHex)
                        put("public_key", c.publicKeyFormatted)
                        put("public_key_algorithm", c.publicKeyAlgorithm)
                        c.publicKeySizeBits?.let { put("public_key_size_bits", it) }
                        put("signature_base64", c.signatureBase64)
                        c.rawCryptographicSignatureBase64?.let { put("raw_pkcs7_or_v4_signature_base64", it) }
                        put("source_schemes", JSONArray(c.sourceSchemes))
                        c.basicConstraintsSummary?.let { put("basic_constraints", it) }
                        put("key_usage", JSONArray(c.keyUsageList))
                        put("extended_key_usage", JSONArray(c.extendedKeyUsageList))
                        c.subjectKeyIdentifierHex?.let { put("subject_key_identifier_hex", it) }
                        c.authorityKeyIdentifierHex?.let { put("authority_key_identifier_hex", it) }
                        put("extension_oids", JSONArray(c.extensionOidsSummary))
                        put("cryptographic_warnings", JSONArray(c.cryptographicWarnings))
                    })
                }
            })

            put("errors", JSONArray(report.globalErrors))
            put("warnings", JSONArray(report.globalWarnings))
            if (includeTerminalText) {
                put("terminal_report", formatTerminalReport(report, detailLevel))
            }
        }
    }
}
