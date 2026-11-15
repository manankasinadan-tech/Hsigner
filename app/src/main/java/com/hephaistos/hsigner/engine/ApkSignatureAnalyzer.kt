package com.hephaistos.hsigner.engine

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.android.apksig.ApkVerifier
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Moteur principal de vérification et d'analyse cryptographique des signatures APK.
 * Combine Google apksig (V1, V2, V3, V3.1, V4), l'inspecteur binaire de blocs APK Signing Block
 * et l'analyse X.509 complète.
 */
class ApkSignatureAnalyzer(private val context: Context? = null) {

    fun analyze(
        apkFile: File,
        displayPath: String = apkFile.absolutePath,
        explicitIdsigFile: File? = null,
        includeRawBits: Boolean = true
    ): ApkVerificationReport {
        val parsedManifest = BinaryXmlManifestParser.parseFromApk(apkFile)
        val pmMetadata = resolvePackageManagerMetadata(apkFile)

        val appName = pmMetadata.first
            ?: parsedManifest.appLabel?.takeIf { !it.startsWith("@") }
            ?: parsedManifest.packageName
            ?: apkFile.nameWithoutExtension
        val pkgName = pmMetadata.second ?: parsedManifest.packageName ?: "Inconnu"
        val versionName = pmMetadata.third ?: parsedManifest.versionName ?: "?"
        val versionCode = pmMetadata.fourth ?: parsedManifest.versionCode ?: 0L

        val metadata = ApkMetadata(
            appName = appName,
            packageName = pkgName,
            versionName = versionName,
            versionCode = versionCode,
            minSdkVersion = parsedManifest.minSdkVersion,
            targetSdkVersion = parsedManifest.targetSdkVersion,
            displayPath = displayPath,
            fileSizeBytes = apkFile.length()
        )

        val detectedBlocks = ApkSigningBlockInspector.inspect(apkFile)
        val idsigFile = explicitIdsigFile ?: findCompanionIdsig(apkFile, displayPath)
        val v4Summary = idsigFile?.let { ApkSigningBlockInspector.inspectIdsig(it) }

        val verifierBuilder = ApkVerifier.Builder(apkFile)
        if (idsigFile != null && idsigFile.exists()) {
            verifierBuilder.setV4SignatureFile(idsigFile)
        }

        val result = try {
            verifierBuilder.build().verify()
        } catch (_: com.android.apksig.apk.MinSdkVersionException) {
            ApkVerifier.Builder(apkFile).apply {
                if (idsigFile != null && idsigFile.exists()) {
                    setV4SignatureFile(idsigFile)
                }
                setMinCheckedPlatformVersion(parsedManifest.minSdkVersion ?: 24)
            }.build().verify()
        }

        val globalErrors = result.errors.map { it.toString() }.toMutableList()
        val globalWarnings = result.warnings.map { it.toString() }.toMutableList()

        // Sur Android >= 24 (Nougat+), ApkVerifier ignore la vérification V1 lorsque V2/V3 est présent.
        // Si des entrées JAR V1 (META-INF/*.RSA|DSA|EC) existent, on vérifie aussi V1 explicitement (API 21..23).
        val v1SupplementalResult = if (detectedBlocks.hasV1JarEntries && !result.isVerifiedUsingV1Scheme) {
            runCatching {
                ApkVerifier.Builder(apkFile)
                    .setMinCheckedPlatformVersion(21)
                    .setMaxCheckedPlatformVersion(23)
                    .build()
                    .verify()
            }.getOrNull()
        } else null

        val v1EffectiveResult = if (result.isVerifiedUsingV1Scheme || v1SupplementalResult == null) {
            result
        } else {
            v1SupplementalResult
        }

        val v1Present = detectedBlocks.hasV1JarEntries || result.isVerifiedUsingV1Scheme || result.v1SchemeSigners.isNotEmpty()
        val v1Verified = result.isVerifiedUsingV1Scheme || (v1SupplementalResult?.isVerifiedUsingV1Scheme == true)
        val v2Present = detectedBlocks.hasV2Block || result.isVerifiedUsingV2Scheme || result.v2SchemeSigners.isNotEmpty()
        val v3Present = detectedBlocks.hasV3Block || result.isVerifiedUsingV3Scheme || result.v3SchemeSigners.isNotEmpty()
        val v31Present = detectedBlocks.hasV31Block || result.isVerifiedUsingV31Scheme || result.v31SchemeSigners.isNotEmpty()
        val v4Present = (idsigFile != null && idsigFile.exists()) || result.isVerifiedUsingV4Scheme || result.v4SchemeSigners.isNotEmpty()

        val schemeDetails = buildList {
            if (v1Present) {
                add(
                    SchemeVerificationDetail(
                        schemeName = "V1",
                        present = true,
                        verified = v1Verified,
                        signerCount = maxOf(v1EffectiveResult.v1SchemeSigners.size, detectedBlocks.v1SignatureEntryNames.size),
                        algorithms = detectedBlocks.v1SignatureEntryNames,
                        errors = v1EffectiveResult.v1SchemeSigners.flatMap { s -> s.errors.map { it.toString() } },
                        warnings = v1EffectiveResult.v1SchemeSigners.flatMap { s -> s.warnings.map { it.toString() } }
                    )
                )
            }
            if (v2Present) {
                add(
                    SchemeVerificationDetail(
                        schemeName = "V2",
                        present = true,
                        verified = result.isVerifiedUsingV2Scheme,
                        signerCount = result.v2SchemeSigners.size,
                        errors = result.v2SchemeSigners.flatMap { s -> s.errors.map { it.toString() } },
                        warnings = result.v2SchemeSigners.flatMap { s -> s.warnings.map { it.toString() } }
                    )
                )
            }
            if (v3Present) {
                val minSdk = result.v3SchemeSigners.minOfOrNull { it.minSdkVersion }
                val maxSdk = result.v3SchemeSigners.maxOfOrNull { it.maxSdkVersion }
                add(
                    SchemeVerificationDetail(
                        schemeName = "V3",
                        present = true,
                        verified = result.isVerifiedUsingV3Scheme,
                        signerCount = result.v3SchemeSigners.size,
                        minSdkVersion = minSdk,
                        maxSdkVersion = maxSdk,
                        errors = result.v3SchemeSigners.flatMap { s -> s.errors.map { it.toString() } },
                        warnings = result.v3SchemeSigners.flatMap { s -> s.warnings.map { it.toString() } }
                    )
                )
            }
            if (v31Present) {
                val rotMin = result.v31SchemeSigners.minOfOrNull { it.minSdkVersion }
                val rotMax = result.v31SchemeSigners.maxOfOrNull { it.maxSdkVersion }
                add(
                    SchemeVerificationDetail(
                        schemeName = "V3.1",
                        present = true,
                        verified = result.isVerifiedUsingV31Scheme,
                        signerCount = result.v31SchemeSigners.size,
                        minSdkVersion = rotMin,
                        maxSdkVersion = rotMax,
                        rotationMinSdkVersion = rotMin,
                        errors = result.v31SchemeSigners.flatMap { s -> s.errors.map { it.toString() } },
                        warnings = result.v31SchemeSigners.flatMap { s -> s.warnings.map { it.toString() } }
                    )
                )
            }
            if (v4Present) {
                add(
                    SchemeVerificationDetail(
                        schemeName = "V4",
                        present = true,
                        verified = result.isVerifiedUsingV4Scheme,
                        signerCount = maxOf(result.v4SchemeSigners.size, if (v4Summary != null) 1 else 0),
                        companionPath = idsigFile?.absolutePath,
                        errors = result.v4SchemeSigners.flatMap { s -> s.errors.map { it.toString() } },
                        warnings = result.v4SchemeSigners.flatMap { s -> s.warnings.map { it.toString() } }
                    )
                )
            }
        }

        val detectedSchemes = schemeDetails.map { it.schemeName }
        val verifiedSchemes = schemeDetails.filter { it.verified }.map { it.schemeName }
        val schemeSummary = when {
            verifiedSchemes.isNotEmpty() -> verifiedSchemes.joinToString(" + ")
            detectedSchemes.isNotEmpty() -> detectedSchemes.joinToString(" + ") + " (NON VÉRIFIÉ)"
            else -> "Aucun schéma de signature détecté"
        }

        // Collecte dédupliquée des certificats avec suivi des schémas d'origine
        val certMap = linkedMapOf<String, Pair<X509Certificate, MutableSet<String>>>()
        fun addCert(cert: X509Certificate?, scheme: String) {
            if (cert == null) return
            val key = CertificateCryptoExtractor.digestHex(cert.encoded, "SHA-256")
            val entry = certMap.getOrPut(key) { cert to linkedSetOf() }
            if (scheme.isNotBlank()) entry.second.add(scheme)
        }

        (result.v1SchemeSigners + (v1SupplementalResult?.v1SchemeSigners ?: emptyList())).forEach { signer ->
            addCert(signer.certificate, "V1")
            signer.certificateChain.forEach { addCert(it, "V1") }
        }
        result.v2SchemeSigners.forEach { signer ->
            signer.certificates.forEach { addCert(it, "V2") }
        }
        result.v3SchemeSigners.forEach { signer ->
            signer.certificates.forEach { addCert(it, "V3") }
        }
        result.v31SchemeSigners.forEach { signer ->
            signer.certificates.forEach { addCert(it, "V3.1") }
        }
        result.v4SchemeSigners.forEach { signer ->
            signer.certificates.forEach { addCert(it, "V4") }
        }
        result.signerCertificates.forEach { cert ->
            addCert(cert, "")
        }

        // Fallback si aucun certificat remonté par apksig (ex. APK corrompu avec bloc PKCS#7 présent)
        if (certMap.isEmpty() && detectedBlocks.v1RawPkcs7SignatureBytes != null) {
            runCatching {
                val cf = CertificateFactory.getInstance("X.509")
                val certs = cf.generateCertificates(ByteArrayInputStream(detectedBlocks.v1RawPkcs7SignatureBytes))
                certs.filterIsInstance<X509Certificate>().forEach { addCert(it, "V1 (Brut)") }
            }
        }

        val certificates = certMap.values.mapIndexed { idx, (cert, schemes) ->
            val rawSig = if (idx == 0) {
                detectedBlocks.v1RawPkcs7SignatureBytes ?: v4Summary?.rawSignatureBytes
            } else {
                null
            }
            CertificateCryptoExtractor.extract(
                index = idx + 1,
                certificate = cert,
                sourceSchemes = schemes.toList(),
                rawSignatureBytes = rawSig
            ).let { details ->
                if (includeRawBits) details else details.copy(signatureBitsHex = "(masqué)")
            }
        }

        val lineageNodes = result.signingCertificateLineage?.certificatesInLineage?.mapIndexed { i, cert ->
            LineageCertificateNode(
                index = i + 1,
                subjectDn = cert.subjectX500Principal.name,
                sha256 = CertificateCryptoExtractor.digestHex(cert.encoded, "SHA-256"),
                flags = 0
            )
        } ?: emptyList()

        val stampInfo = result.sourceStampInfo
        val stampSubject = stampInfo?.certificate?.subjectX500Principal?.name
        val stampVerified = stampInfo != null && stampInfo.errors.isEmpty()

        return ApkVerificationReport(
            metadata = metadata,
            isVerified = result.isVerified,
            schemeSummary = schemeSummary,
            detectedSchemes = detectedSchemes,
            verifiedSchemes = verifiedSchemes,
            schemeDetails = schemeDetails,
            sourceStampPresent = detectedBlocks.hasSourceStampBlock || stampInfo != null,
            sourceStampVerified = stampVerified,
            sourceStampSubject = stampSubject,
            v3Lineage = lineageNodes,
            certificates = certificates,
            globalErrors = globalErrors,
            globalWarnings = globalWarnings
        )
    }

    private fun findCompanionIdsig(apkFile: File, displayPath: String): File? {
        val adjacent = File(apkFile.absolutePath + ".idsig")
        if (adjacent.exists() && adjacent.isFile) return adjacent
        if (!displayPath.startsWith("content://")) {
            val orig = File("$displayPath.idsig")
            if (orig.exists() && orig.isFile) return orig
        }
        return null
    }

    private data class Quadruple<out A, out B, out C, out D>(val first: A, val second: B, val third: C, val fourth: D)

    private fun resolvePackageManagerMetadata(apkFile: File): Quadruple<String?, String?, String?, Long?> {
        val ctx = context ?: return Quadruple(null, null, null, null)
        return runCatching {
            val pm = ctx.packageManager
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.PackageInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageArchiveInfo(apkFile.absolutePath, 0)
            } ?: return Quadruple(null, null, null, null)

            info.applicationInfo?.let { appInfo ->
                appInfo.sourceDir = apkFile.absolutePath
                appInfo.publicSourceDir = apkFile.absolutePath
            }

            val label = info.applicationInfo?.loadLabel(pm)?.toString()?.takeIf { it.isNotBlank() }
            val vCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                info.versionCode.toLong()
            }
            Quadruple(label, info.packageName, info.versionName, vCode)
        }.getOrDefault(Quadruple(null, null, null, null))
    }
}
