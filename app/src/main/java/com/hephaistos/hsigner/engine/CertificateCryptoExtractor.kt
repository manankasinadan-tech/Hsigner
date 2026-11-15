package com.hephaistos.hsigner.engine

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.text.DateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.zip.CRC32
import javax.security.auth.x500.X500Principal

/**
 * Extracteur cryptographique complet des propriétés d'un certificat X.509 et de sa signature :
 * - Tous les condensats (CRC32, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512)
 * - Empreintes formatées Play Console / Firebase (SHA-1 & SHA-256 majuscules avec ':')
 * - Pin SPKI (SubjectPublicKeyInfo SHA-256 Hex & Base64)
 * - Extensions X.509 v3 (BasicConstraints, KeyUsage, ExtendedKeyUsage, SKI, AKI, OIDs)
 * - Audit temporel et détection des faiblesses cryptographiques (Debug, expiré, SHA1, RSA < 2048)
 */
object CertificateCryptoExtractor {

    private val KEY_USAGE_NAMES = listOf(
        "digitalSignature",
        "nonRepudiation (contentCommitment)",
        "keyEncipherment",
        "dataEncipherment",
        "keyAgreement",
        "keyCertSign",
        "cRLSign",
        "encipherOnly",
        "decipherOnly"
    )

    private val KNOWN_EXTENSION_OIDS = mapOf(
        "2.5.29.14" to "SubjectKeyIdentifier (SKI)",
        "2.5.29.15" to "KeyUsage",
        "2.5.29.17" to "SubjectAlternativeName",
        "2.5.29.19" to "BasicConstraints",
        "2.5.29.31" to "CRLDistributionPoints",
        "2.5.29.32" to "CertificatePolicies",
        "2.5.29.35" to "AuthorityKeyIdentifier (AKI)",
        "2.5.29.37" to "ExtendedKeyUsage",
        "1.3.6.1.5.5.7.1.1" to "AuthorityInfoAccess"
    )

    fun extract(
        index: Int,
        certificate: X509Certificate,
        sourceSchemes: List<String>,
        rawSignatureBytes: ByteArray? = null,
        nowEpochMs: Long = System.currentTimeMillis()
    ): CertificateDetails {
        val der = certificate.encoded
        val hashCode = der.contentHashCode()
        val hashCodeHex = "0x" + Integer.toHexString(hashCode)

        val crc = CRC32().apply { update(der) }.value
        val crcHex = "%08x".format(crc)

        val md5 = digestHex(der, "MD5")
        val sha1 = digestHex(der, "SHA-1")
        val sha224 = digestHex(der, "SHA-224")
        val sha256 = digestHex(der, "SHA-256")
        val sha384 = digestHex(der, "SHA-384")
        val sha512 = digestHex(der, "SHA-512")

        val sha1Colon = toColonUpperHex(sha1)
        val sha256Colon = toColonUpperHex(sha256)

        val spkiBytes = certificate.publicKey.encoded
        val spkiSha256Bytes = MessageDigest.getInstance("SHA-256").digest(spkiBytes)
        val spkiSha256Hex = bytesToHex(spkiSha256Bytes)
        val spkiSha256Base64 = encodeBase64NoWrap(spkiSha256Bytes)

        val subjectDn = certificate.subjectX500Principal.getName(X500Principal.RFC2253)
        val issuerDn = certificate.issuerX500Principal.getName(X500Principal.RFC2253)
        val isSelfSigned = certificate.issuerX500Principal == certificate.subjectX500Principal
        val subjectComponents = parseDnComponents(subjectDn)

        val frDateFormat = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.FRANCE)
        val validFromStr = frDateFormat.format(certificate.notBefore)
        val validToStr = frDateFormat.format(certificate.notAfter)

        val notBeforeMs = certificate.notBefore.time
        val notAfterMs = certificate.notAfter.time
        val durationDays = TimeUnit.MILLISECONDS.toDays((notAfterMs - notBeforeMs).coerceAtLeast(0L))
        val isCurrentlyValid = nowEpochMs in notBeforeMs..notAfterMs
        val validityStatus = when {
            nowEpochMs < notBeforeMs -> {
                val daysUntil = TimeUnit.MILLISECONDS.toDays(notBeforeMs - nowEpochMs)
                "Pas encore valide (début dans $daysUntil jour(s))"
            }
            nowEpochMs > notAfterMs -> {
                val daysExpired = TimeUnit.MILLISECONDS.toDays(nowEpochMs - notAfterMs)
                "EXPIRÉ depuis $daysExpired jour(s)"
            }
            else -> {
                val daysLeft = TimeUnit.MILLISECONDS.toDays(notAfterMs - nowEpochMs)
                "Valide actuellement (expire dans $daysLeft jour(s))"
            }
        }

        val serialBigInt = certificate.serialNumber
        val serialDecimal = if (serialBigInt.signum() < 0) {
            java.math.BigInteger(1, serialBigInt.toByteArray()).toString(10)
        } else {
            serialBigInt.toString(10)
        }
        val serialHex = "0x" + serialBigInt.toString(16)

        val certBase64 = encodeBase64NoWrap(der)
        val bitsHex = bytesToHex(der)
        val (pubKeyFormatted, pubKeyAlg, pubKeySizeBits) = formatPublicKey(certificate.publicKey)

        val androidEnvelope = ByteBuffer.allocate(5 + der.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(1.toByte())
            .putInt(der.size)
            .put(der)
            .array()
        val signatureBase64 = encodeBase64NoWrap(androidEnvelope)
        val rawSigB64 = rawSignatureBytes?.let { encodeBase64NoWrap(it) }

        val basicConstraints = when (val bc = certificate.basicConstraints) {
            -1 -> "CA: false (Certificat entité finale)"
            Int.MAX_VALUE -> "CA: true (Autorité sans limite de profondeur)"
            else -> "CA: true (pathLenConstraint=$bc)"
        }

        val keyUsages = certificate.keyUsage?.let { bits ->
            bits.indices.mapNotNull { idx ->
                if (bits[idx]) KEY_USAGE_NAMES.getOrNull(idx) ?: "bit_$idx" else null
            }
        } ?: emptyList()

        val extKeyUsages = runCatching { certificate.extendedKeyUsage ?: emptyList() }.getOrDefault(emptyList())

        val skiHex = extractExtensionOctetHex(certificate, "2.5.29.14")
        val akiHex = extractExtensionOctetHex(certificate, "2.5.29.35")

        val extOids = buildList {
            certificate.criticalExtensionOIDs?.forEach { oid ->
                val label = KNOWN_EXTENSION_OIDS[oid] ?: "Extension"
                add("[CRITIQUE] $oid ($label)")
            }
            certificate.nonCriticalExtensionOIDs?.forEach { oid ->
                val label = KNOWN_EXTENSION_OIDS[oid] ?: "Extension"
                add("$oid ($label)")
            }
        }

        val isDebugCert = subjectDn.contains("Android Debug", ignoreCase = true) ||
            issuerDn.contains("Android Debug", ignoreCase = true)

        val warnings = mutableListOf<String>()
        if (isDebugCert) {
            warnings.add("Certificat DEBUG Android standard détecté (ne pas distribuer en production).")
        }
        if (!isCurrentlyValid) {
            warnings.add("Certificat hors période de validité ($validityStatus).")
        }
        val sigAlgUpper = (certificate.sigAlgName ?: "").uppercase()
        if (sigAlgUpper.contains("MD5")) {
            warnings.add("Algorithme de signature MD5 cryptographiquement cassé.")
        } else if (sigAlgUpper.contains("SHA1")) {
            warnings.add("Algorithme hérité SHA-1 détecté sur le certificat X.509 (SHA-256 recommandé pour nouveaux certificats).")
        }
        if (pubKeyAlg == "RSA" && pubKeySizeBits != null && pubKeySizeBits < 2048) {
            warnings.add("Clé RSA courte ($pubKeySizeBits bits ; >= 2048 bits recommandé).")
        }

        return CertificateDetails(
            index = index,
            certificateType = certificate.type ?: "X.509",
            version = certificate.version,
            serialNumberDecimal = serialDecimal,
            serialNumberHex = serialHex,
            subjectDn = subjectDn,
            issuerDn = issuerDn,
            isSelfSigned = isSelfSigned,
            validFromEpochMs = notBeforeMs,
            validToEpochMs = notAfterMs,
            validFromFormatted = validFromStr,
            validToFormatted = validToStr,
            signatureAlgorithm = certificate.sigAlgName ?: "Unknown",
            hashCodeHex = hashCodeHex,
            hashCodeInt = hashCode,
            crc32Hex = crcHex,
            crc32Decimal = crc,
            md5Hex = md5,
            sha1Hex = sha1,
            sha224Hex = sha224,
            sha256Hex = sha256,
            sha384Hex = sha384,
            sha512Hex = sha512,
            certificateBase64 = certBase64,
            signatureBitsHex = bitsHex,
            publicKeyFormatted = pubKeyFormatted,
            publicKeyAlgorithm = pubKeyAlg,
            publicKeySizeBits = pubKeySizeBits,
            signatureBase64 = signatureBase64,
            rawCryptographicSignatureBase64 = rawSigB64,
            sourceSchemes = sourceSchemes,
            sha1ColonUpper = sha1Colon,
            sha256ColonUpper = sha256Colon,
            spkiSha256Hex = spkiSha256Hex,
            spkiSha256Base64 = spkiSha256Base64,
            subjectComponents = subjectComponents,
            validityStatusLabel = validityStatus,
            validityDurationDays = durationDays,
            isCurrentlyValid = isCurrentlyValid,
            isDebugCertificate = isDebugCert,
            basicConstraintsSummary = basicConstraints,
            keyUsageList = keyUsages,
            extendedKeyUsageList = extKeyUsages,
            subjectKeyIdentifierHex = skiHex,
            authorityKeyIdentifierHex = akiHex,
            extensionOidsSummary = extOids,
            cryptographicWarnings = warnings
        )
    }

    private fun extractExtensionOctetHex(cert: X509Certificate, oid: String): String? {
        val raw = cert.getExtensionValue(oid) ?: return null
        if (raw.size <= 2) return bytesToHex(raw)
        // Extension value is wrapped in an OCTET STRING (0x04 len ...)
        return if (raw[0].toInt() == 0x04) {
            val innerLen = raw[1].toInt() and 0xFF
            if (innerLen < 128 && raw.size >= 2 + innerLen) {
                bytesToHex(raw.copyOfRange(2, 2 + innerLen))
            } else {
                bytesToHex(raw)
            }
        } else {
            bytesToHex(raw)
        }
    }

    private fun parseDnComponents(rfc2253: String): Map<String, String> {
        val map = linkedMapOf<String, String>()
        // Split on unescaped commas
        val parts = rfc2253.split(Regex("(?<!\\\\),"))
        for (part in parts) {
            val eqIdx = part.indexOf('=')
            if (eqIdx > 0) {
                val key = part.substring(0, eqIdx).trim()
                val value = part.substring(eqIdx + 1).trim()
                val friendlyKey = if (key == "1.2.840.113549.1.9.1") "EMAIL (1.2.840.113549.1.9.1)" else key
                map[friendlyKey] = value
            }
        }
        return map
    }

    private fun toColonUpperHex(hex: String): String {
        if (hex.length < 2) return hex.uppercase()
        return hex.uppercase().chunked(2).joinToString(":")
    }

    private fun formatPublicKey(publicKey: PublicKey): Triple<String, String, Int?> {
        return when (publicKey) {
            is RSAPublicKey -> {
                val modHex = publicKey.modulus.toString(16)
                val exp = publicKey.publicExponent.toString(10)
                val formatted = "OpenSSLRSAPublicKey{modulus=$modHex,publicExponent=$exp}"
                Triple(formatted, "RSA", publicKey.modulus.bitLength())
            }
            is ECPublicKey -> {
                val w = publicKey.w
                val fieldSize = publicKey.params?.curve?.field?.fieldSize ?: 0
                val formatted = "ECPublicKey{bits=$fieldSize,x=${w.affineX.toString(16)},y=${w.affineY.toString(16)}}"
                Triple(formatted, "EC", if (fieldSize > 0) fieldSize else null)
            }
            is DSAPublicKey -> {
                val yHex = publicKey.y.toString(16)
                val bits = publicKey.params?.p?.bitLength()
                val formatted = "DSAPublicKey{y=$yHex,bits=${bits ?: "?"}}"
                Triple(formatted, "DSA", bits)
            }
            else -> {
                val encodedHex = bytesToHex(publicKey.encoded)
                Triple("${publicKey.algorithm}{encoded=$encodedHex}", publicKey.algorithm, null)
            }
        }
    }

    fun digestHex(bytes: ByteArray, algorithm: String): String {
        val digest = runCatching { MessageDigest.getInstance(algorithm).digest(bytes) }
            .getOrElse { return "Non disponible ($algorithm)" }
        return bytesToHex(digest)
    }

    fun bytesToHex(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        val digits = "0123456789abcdef"
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = digits[v ushr 4]
            hexChars[i * 2 + 1] = digits[v and 0x0F]
        }
        return String(hexChars)
    }

    fun encodeBase64NoWrap(input: ByteArray): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val out = StringBuilder(((input.size + 2) / 3) * 4)
        var i = 0
        while (i < input.size) {
            val b0 = input[i].toInt() and 0xFF
            val hasB1 = i + 1 < input.size
            val hasB2 = i + 2 < input.size
            val b1 = if (hasB1) input[i + 1].toInt() and 0xFF else 0
            val b2 = if (hasB2) input[i + 2].toInt() and 0xFF else 0

            out.append(alphabet[b0 ushr 2])
            out.append(alphabet[((b0 and 0x03) shl 4) or (b1 ushr 4)])
            out.append(if (hasB1) alphabet[((b1 and 0x0F) shl 2) or (b2 ushr 6)] else '=')
            out.append(if (hasB2) alphabet[b2 and 0x3F] else '=')
            i += 3
        }
        return out.toString()
    }
}
