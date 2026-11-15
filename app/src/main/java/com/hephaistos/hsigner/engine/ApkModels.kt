package com.hephaistos.hsigner.engine

/**
 * Métadonnées applicatives et flags de sécurité extraits de l'APK analysé.
 */
data class ApkMetadata(
    val appName: String,
    val packageName: String,
    val versionName: String,
    val versionCode: Long,
    val minSdkVersion: Int?,
    val targetSdkVersion: Int?,
    val compileSdkVersion: Int? = null,
    val displayPath: String,
    val fileSizeBytes: Long,
    val debuggable: Boolean? = null,
    val allowBackup: Boolean? = null,
    val usesCleartextTraffic: Boolean? = null,
    val testOnly: Boolean? = null,
    val permissions: List<String> = emptyList()
)

/**
 * Empreintes cryptographiques du fichier APK complet et structure interne ZIP.
 */
data class ApkFileForensics(
    val fileSizeBytes: Long,
    val crc32Hex: String,
    val md5Hex: String,
    val sha1Hex: String,
    val sha256Hex: String,
    val sha512Hex: String,
    val totalZipEntries: Int,
    val dexCount: Int,
    val nativeLibrariesCount: Int,
    val nativeAbis: List<String>,
    val hasResourcesArsc: Boolean,
    val hasKotlinMetadata: Boolean
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
    val contentDigests: List<String> = emptyList(),
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
    val sourceSchemes: List<String>,
    // Champs d'audit X.509 avancés
    val sha1ColonUpper: String = "",
    val sha256ColonUpper: String = "",
    val spkiSha256Hex: String = "",
    val spkiSha256Base64: String = "",
    val subjectComponents: Map<String, String> = emptyMap(),
    val validityStatusLabel: String = "",
    val validityDurationDays: Long = 0L,
    val isCurrentlyValid: Boolean = true,
    val isDebugCertificate: Boolean = false,
    val basicConstraintsSummary: String? = null,
    val keyUsageList: List<String> = emptyList(),
    val extendedKeyUsageList: List<String> = emptyList(),
    val subjectKeyIdentifierHex: String? = null,
    val authorityKeyIdentifierHex: String? = null,
    val extensionOidsSummary: List<String> = emptyList(),
    val cryptographicWarnings: List<String> = emptyList()
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
    val globalWarnings: List<String>,
    val fileForensics: ApkFileForensics? = null,
    val signingBlockSizeBytes: Long? = null,
    val signingBlockIdsNamed: List<String> = emptyList(),
    val securityRating: String = "",
    val securityAssessments: List<String> = emptyList()
)
