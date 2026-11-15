package com.hephaistos.hsigner.engine

/**
 * Métadonnées applicatives extraites de l'APK analysé.
 */
data class ApkMetadata(
    val appName: String,
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val minSdkVersion: Int?,
    val targetSdkVersion: Int?,
    val displayPath: String,
    val fileSizeBytes: Long
)

/**
 * Détails d'un schéma de signature (V1, V2, V3, V3.1 ou V4).
 */
data class SchemeVerificationDetail(
    val schemeName: String,
    val present: Boolean,
    val verified: Boolean,
    val signerCount: Int,
    val algorithms: List<String> = emptyList(),
    val minSdkVersion: Int? = null,
    val maxSdkVersion: Int? = null,
    val rotationMinSdkVersion: Int? = null,
    val companionPath: String? = null,
    val errors: List<String> = emptyList(),
    val warnings: List<String> = emptyList()
)

/**
 * Noeud d'historique de rotation de clés (Signing Certificate Lineage V3 / V3.1).
 */
data class LineageCertificateNode(
    val index: Int,
    val subjectDn: String,
    val sha256: String,
    val flags: Int
)

/**
 * Propriétés cryptographiques complètes d'un certificat X.509 et de sa signature associée.
 */
data class CertificateDetails(
    val index: Int,
    val certificateType: String,
    val version: Int,
    val serialNumberDecimal: String,
    val serialNumberHex: String,
    val subjectDn: String,
    val issuerDn: String,
    val isSelfSigned: Boolean,
    val validFromEpochMs: Long,
    val validToEpochMs: Long,
    val validFromFormatted: String,
    val validToFormatted: String,
    val signatureAlgorithm: String,
    val hashCodeHex: String,
    val hashCodeInt: Int,
    val crc32Hex: String,
    val crc32Decimal: Long,
    val md5Hex: String,
    val sha1Hex: String,
    val sha224Hex: String,
    val sha256Hex: String,
    val sha384Hex: String,
    val sha512Hex: String,
    val certificateBase64: String,
    val signatureBitsHex: String,
    val publicKeyFormatted: String,
    val publicKeyAlgorithm: String,
    val publicKeySizeBits: Int?,
    val signatureBase64: String,
    val rawCryptographicSignatureBase64: String?,
    val sourceSchemes: List<String>
)

/**
 * Résultat complet de vérification d'un APK.
 */
data class ApkVerificationReport(
    val metadata: ApkMetadata,
    val isVerified: Boolean,
    val schemeSummary: String,
    val detectedSchemes: List<String>,
    val verifiedSchemes: List<String>,
    val schemeDetails: List<SchemeVerificationDetail>,
    val sourceStampPresent: Boolean,
    val sourceStampVerified: Boolean,
    val sourceStampSubject: String?,
    val v3Lineage: List<LineageCertificateNode>,
    val certificates: List<CertificateDetails>,
    val globalErrors: List<String>,
    val globalWarnings: List<String>
)
