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
import java.util.zip.CRC32
import javax.security.auth.x500.X500Principal

/**
 * Extracteur cryptographique complet des propriétés d'un certificat X.509 et de sa signature.
 * Produit les empreintes exactes (CRC32, MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512),
 * le code de hachage signé/hexadécimal, le DER hexadécimal, les Base64 et la description de clé publique.
 */
object CertificateCryptoExtractor {

    fun extract(
        index: Int,
        certificate: X509Certificate,
        sourceSchemes: List<String>,
        rawSignatureBytes: ByteArray? = null
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

        val subjectDn = certificate.subjectX500Principal.getName(X500Principal.RFC2253)
        val issuerDn = certificate.issuerX500Principal.getName(X500Principal.RFC2253)
        val isSelfSigned = certificate.issuerX500Principal == certificate.subjectX500Principal

        val frDateFormat = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.FRANCE)
        val validFromStr = frDateFormat.format(certificate.notBefore)
        val validToStr = frDateFormat.format(certificate.notAfter)

        val serialBigInt = certificate.serialNumber
        val serialDecimal = if (serialBigInt.signum() < 0) {
            java.math.BigInteger(1, serialBigInt.toByteArray()).toString(10)
        } else {
            serialBigInt.toString(10)
        }
        val serialHex = serialBigInt.toString(16)

        val certBase64 = encodeBase64NoWrap(der)
        val bitsHex = bytesToHex(der)
        val (pubKeyFormatted, pubKeyAlg, pubKeySizeBits) = formatPublicKey(certificate.publicKey)

        // Format Android SigningInfo/PackageSignature envelope (1 byte cert count + 4-byte BE length + DER)
        val androidEnvelope = ByteBuffer.allocate(5 + der.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(1.toByte())
            .putInt(der.size)
            .put(der)
            .array()
        val signatureBase64 = encodeBase64NoWrap(androidEnvelope)
        val rawSigB64 = rawSignatureBytes?.let { encodeBase64NoWrap(it) }

        return CertificateDetails(
            index = index,
            certificateType = certificate.type ?: "X.509",
            version = certificate.version,
            serialNumberDecimal = serialDecimal,
            serialNumberHex = serialHex,
            subjectDn = subjectDn,
            issuerDn = issuerDn,
            isSelfSigned = isSelfSigned,
            validFromEpochMs = certificate.notBefore.time,
            validToEpochMs = certificate.notAfter.time,
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
            sourceSchemes = sourceSchemes
        )
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
