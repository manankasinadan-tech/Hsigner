package com.hephaistos.hsigner

import com.android.apksig.ApkSigner
import com.hephaistos.hsigner.engine.ApkSignatureAnalyzer
import com.hephaistos.hsigner.engine.BinaryXmlManifestParser
import com.hephaistos.hsigner.engine.SignatureReportFormatter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class HsignerEngineTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `analyze detects V1 V2 V3 V4 signatures and formats full French report`() {
        val rawApk = tempFolder.newFile("unsigned.apk")
        val axmlBytes = buildMinimalAxmlManifest(
            packageName = "com.hephaistos.sample",
            versionName = "16",
            versionCode = 36,
            minSdk = 24,
            targetSdk = 35,
            appLabel = "Gestionnaire Test"
        )
        createMinimalApk(rawApk, axmlBytes)

        val parsed = BinaryXmlManifestParser.parseFromApk(rawApk)
        assertEquals("com.hephaistos.sample", parsed.packageName)
        assertEquals("16", parsed.versionName)
        assertEquals(36L, parsed.versionCode)
        assertEquals(24, parsed.minSdkVersion)
        assertEquals(35, parsed.targetSdkVersion)
        assertEquals("Gestionnaire Test", parsed.appLabel)

        val (privateKey, cert) = generateSelfSignedRsaCert()
        val signerConfig = ApkSigner.SignerConfig.Builder(
            "TESTKEY",
            privateKey,
            listOf(cert)
        ).build()

        val signedApk = tempFolder.newFile("signed_app.apk")
        val idsigFile = File(signedApk.absolutePath + ".idsig")

        ApkSigner.Builder(listOf(signerConfig))
            .setInputApk(rawApk)
            .setOutputApk(signedApk)
            .setMinSdkVersion(21)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setV4SigningEnabled(true)
            .setV4SignatureOutputFile(idsigFile)
            .build()
            .sign()

        val analyzer = ApkSignatureAnalyzer(context = null)
        val report = analyzer.analyze(
            apkFile = signedApk,
            displayPath = "/storage/emulated/0/Download/signed_app.apk",
            explicitIdsigFile = idsigFile,
            includeRawBits = true
        )

        assertTrue(
            "APK should be verified; errors=${report.globalErrors}, schemeErrors=${report.schemeDetails.map { it.schemeName to it.errors }}",
            report.isVerified
        )
        assertEquals("Gestionnaire Test", report.metadata.appName)
        assertEquals("16", report.metadata.versionName)
        assertEquals(36L, report.metadata.versionCode)
        assertTrue("V1 should be verified", report.verifiedSchemes.contains("V1"))
        assertTrue("V2 should be verified", report.verifiedSchemes.contains("V2"))
        assertTrue("V3 should be verified", report.verifiedSchemes.contains("V3"))
        assertTrue("V4 should be verified", report.verifiedSchemes.contains("V4"))
        assertEquals(1, report.certificates.size)

        val c = report.certificates.first()
        assertEquals("X.509", c.certificateType)
        assertEquals(3, c.version)
        assertTrue(c.isSelfSigned)
        assertTrue(c.sha256Hex.length == 64)
        assertTrue(c.sha512Hex.length == 128)
        assertTrue(c.sha224Hex.length == 56)
        assertTrue(c.sha384Hex.length == 96)
        assertTrue(c.md5Hex.length == 32)
        assertTrue(c.crc32Hex.length == 8)
        assertTrue(c.sha1ColonUpper.contains(":"))
        assertTrue(c.sha256ColonUpper.contains(":"))
        assertTrue(c.spkiSha256Hex.length == 64)
        assertTrue(c.spkiSha256Base64.isNotBlank())
        assertEquals("RSA", c.publicKeyAlgorithm)
        assertEquals(2048, c.publicKeySizeBits)
        assertTrue(c.publicKeyFormatted.startsWith("OpenSSLRSAPublicKey{modulus="))
        assertTrue(c.signatureBitsHex.startsWith("3082"))

        val forensics = report.fileForensics
        assertTrue(forensics != null)
        assertTrue(forensics!!.sha256Hex.length == 64)
        assertTrue(forensics.totalZipEntries >= 2)
        assertTrue(report.securityRating.isNotBlank())
        assertTrue(report.signingBlockSizeBytes != null && report.signingBlockSizeBytes!! > 0L)

        val textReport = SignatureReportFormatter.formatTerminalReport(report, "ultra_complet")
        assertTrue(textReport.contains("Vérification de la signature: Gestionnaire Test v16 (36)"))
        assertTrue(textReport.contains("Chemin: /storage/emulated/0/Download/signed_app.apk"))
        assertTrue(textReport.contains("Schéma de signature : V1 + V2 + V3 + V4"))
        assertTrue(textReport.contains("CERTIFICAT №1"))
        assertTrue(textReport.contains("Auto-signé par le propriétaire du certificat"))
        assertTrue(textReport.contains("Signature CRC32 :"))
        assertTrue(textReport.contains("Signature SHA-224 :"))
        assertTrue(textReport.contains("Base64 du certificat :"))
        assertTrue(textReport.contains("Bits de signature :"))
        assertTrue(textReport.contains("Base64 de signature :"))
        assertTrue(textReport.contains("PROPRIÉTÉS X.509 AVANCÉES & EMPREINTES CONSOLE"))
        assertTrue(textReport.contains("Pin SPKI SHA-256 (Base64) : sha256/"))
        assertTrue(textReport.contains("EMPREINTES & STRUCTURE DU FICHIER APK"))
        assertTrue(textReport.contains("APK SHA-256 :"))
        assertTrue(textReport.contains("MANIFESTE & PROFIL SÉCURITÉ APK"))
        assertTrue(textReport.contains("AUDIT TECHNIQUE V1 / V2 / V3 / V3.1 / V4"))
        assertTrue(textReport.contains("SYNTHÈSE & NIVEAU DE CONFIANCE"))

        val compactReport = SignatureReportFormatter.formatTerminalReport(report, "compact")
        assertTrue(compactReport.contains("Vérification de la signature: Gestionnaire Test v16 (36)"))
        assertTrue(!compactReport.contains("Base64 du certificat :"))

        val json = SignatureReportFormatter.toJson(report)
        assertTrue(json.getBoolean("verified"))
        assertEquals("V1 + V2 + V3 + V4", json.getString("scheme_summary"))
        assertEquals(1, json.getJSONArray("certificates").length())
        assertTrue(json.has("apk_file_forensics"))
        assertTrue(json.getString("security_rating").isNotBlank())
        val certJson = json.getJSONArray("certificates").getJSONObject(0)
        assertTrue(certJson.has("spki_sha256_base64"))
        assertTrue(certJson.has("sha256_colon_upper"))
    }

    private fun createMinimalApk(target: File, axmlBytes: ByteArray) {
        ZipOutputStream(target.outputStream()).use { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write(axmlBytes)
            zos.closeEntry()

            zos.putNextEntry(ZipEntry("assets/hello.txt"))
            zos.write("HSIGNER".toByteArray())
            zos.closeEntry()
        }
    }

    /**
     * Construit un AndroidManifest.xml binaire (AXML) valide avec StringPool, ResourceMap
     * et balises manifest / uses-sdk / application pour tester à la fois ApkVerifier et BinaryXmlManifestParser.
     */
    private fun buildMinimalAxmlManifest(
        packageName: String,
        versionName: String,
        versionCode: Int,
        minSdk: Int,
        targetSdk: Int,
        appLabel: String
    ): ByteArray {
        val strings = listOf(
            "versionCode",      // 0
            "versionName",      // 1
            "minSdkVersion",    // 2
            "targetSdkVersion", // 3
            "label",            // 4
            "package",          // 5
            "manifest",         // 6
            "uses-sdk",         // 7
            "application",      // 8
            "http://schemas.android.com/apk/res/android", // 9
            packageName,        // 10
            versionName,        // 11
            appLabel            // 12
        )

        val stringPoolChunk = buildUtf16StringPool(strings)
        val resMapIds = intArrayOf(0x0101021b, 0x0101021c, 0x0101020c, 0x01010270, 0x01010001)
        val resMapBuf = ByteBuffer.allocate(8 + resMapIds.size * 4).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0x00080180)
            putInt(8 + resMapIds.size * 4)
            resMapIds.forEach { putInt(it) }
        }.array()

        val nsUriIdx = 9
        val manifestStart = buildStartTagChunk(
            tagNameIdx = 6,
            attrs = listOf(
                Attr(-1, 5, 10, 0x03, 10),         // package
                Attr(nsUriIdx, 0, -1, 0x10, versionCode), // android:versionCode
                Attr(nsUriIdx, 1, 11, 0x03, 11)    // android:versionName
            )
        )
        val usesSdkStart = buildStartTagChunk(
            tagNameIdx = 7,
            attrs = listOf(
                Attr(nsUriIdx, 2, -1, 0x10, minSdk),
                Attr(nsUriIdx, 3, -1, 0x10, targetSdk)
            )
        )
        val usesSdkEnd = buildEndTagChunk(7)
        val appStart = buildStartTagChunk(
            tagNameIdx = 8,
            attrs = listOf(
                Attr(nsUriIdx, 4, 12, 0x03, 12)
            )
        )
        val appEnd = buildEndTagChunk(8)
        val manifestEnd = buildEndTagChunk(6)

        val bodySize = stringPoolChunk.size + resMapBuf.size +
            manifestStart.size + usesSdkStart.size + usesSdkEnd.size +
            appStart.size + appEnd.size + manifestEnd.size

        return ByteBuffer.allocate(8 + bodySize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0x00080003)
            putInt(8 + bodySize)
            put(stringPoolChunk)
            put(resMapBuf)
            put(manifestStart)
            put(usesSdkStart)
            put(usesSdkEnd)
            put(appStart)
            put(appEnd)
            put(manifestEnd)
        }.array()
    }

    private data class Attr(val nsIdx: Int, val nameIdx: Int, val rawValueIdx: Int, val type: Int, val data: Int)

    private fun buildStartTagChunk(tagNameIdx: Int, attrs: List<Attr>): ByteArray {
        val chunkSize = 36 + attrs.size * 20
        return ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0x00100102)
            putInt(chunkSize)
            putInt(1) // lineNumber
            putInt(-1) // comment
            putInt(-1) // ns
            putInt(tagNameIdx)
            putShort(0x0014.toShort()) // attributeStart
            putShort(0x0014.toShort()) // attributeSize
            putShort(attrs.size.toShort())
            putShort(0) // idIndex
            putShort(0) // classIndex
            putShort(0) // styleIndex
            for (a in attrs) {
                putInt(a.nsIdx)
                putInt(a.nameIdx)
                putInt(a.rawValueIdx)
                putShort(8.toShort())
                put(0.toByte())
                put(a.type.toByte())
                putInt(a.data)
            }
        }.array()
    }

    private fun buildEndTagChunk(tagNameIdx: Int): ByteArray {
        return ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0x00100103)
            putInt(24)
            putInt(1)
            putInt(-1)
            putInt(-1)
            putInt(tagNameIdx)
        }.array()
    }

    private fun buildUtf16StringPool(strings: List<String>): ByteArray {
        val offsets = IntArray(strings.size)
        val stringsOut = ByteArrayOutputStream()
        for ((i, s) in strings.withIndex()) {
            offsets[i] = stringsOut.size()
            val chars = s.toByteArray(Charsets.UTF_16LE)
            stringsOut.write(s.length and 0xFF)
            stringsOut.write((s.length ushr 8) and 0xFF)
            stringsOut.write(chars)
            stringsOut.write(0)
            stringsOut.write(0)
        }
        while (stringsOut.size() % 4 != 0) stringsOut.write(0)

        val headerSize = 28
        val offsetsSize = strings.size * 4
        val stringsOffset = headerSize + offsetsSize
        val totalSize = stringsOffset + stringsOut.size()

        return ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0x001C0001)
            putInt(totalSize)
            putInt(strings.size)
            putInt(0) // styleCount
            putInt(0) // flags (UTF-16)
            putInt(stringsOffset)
            putInt(0) // stylesOffset
            offsets.forEach { putInt(it) }
            put(stringsOut.toByteArray())
        }.array()
    }

    /**
     * Génère un certificat X.509 v3 auto-signé DER pur en Kotlin sans dépendance externe.
     */
    private fun generateSelfSignedRsaCert(): Pair<PrivateKey, X509Certificate> {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()

        val serial = derInteger(BigInteger.valueOf(123456789012345L).toByteArray())
        val sigAlgId = derSequence(
            derOid(byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B)) +
                byteArrayOf(0x05, 0x00)
        )
        val cnAttr = derSet(
            derSequence(
                derOid(byteArrayOf(0x55, 0x04, 0x03)) +
                    derUtf8String("HSIGNER Test Cert")
            )
        )
        val name = derSequence(cnAttr)
        val validity = derSequence(
            derUtcTime("240101000000Z") + derUtcTime("490101000000Z")
        )
        val version = derContextExplicit(0, derInteger(byteArrayOf(0x02))) // v3
        val spki = kp.public.encoded

        val tbsCert = derSequence(version + serial + sigAlgId + name + validity + name + spki)

        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(kp.private)
        sig.update(tbsCert)
        val sigBytes = sig.sign()

        val certDer = derSequence(tbsCert + sigAlgId + derBitString(sigBytes))
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(certDer.inputStream()) as X509Certificate
        return kp.private to cert
    }

    private fun derLength(len: Int): ByteArray {
        return when {
            len < 128 -> byteArrayOf(len.toByte())
            len <= 0xFF -> byteArrayOf(0x81.toByte(), len.toByte())
            else -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
        }
    }

    private fun derTlv(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        out.write(derLength(value.size))
        out.write(value)
        return out.toByteArray()
    }

    private fun derSequence(content: ByteArray) = derTlv(0x30, content)
    private fun derSet(content: ByteArray) = derTlv(0x31, content)
    private fun derInteger(value: ByteArray) = derTlv(0x02, value)
    private fun derOid(value: ByteArray) = derTlv(0x06, value)
    private fun derUtf8String(text: String) = derTlv(0x0C, text.toByteArray(Charsets.UTF_8))
    private fun derUtcTime(text: String) = derTlv(0x17, text.toByteArray(Charsets.US_ASCII))
    private fun derContextExplicit(tagNo: Int, content: ByteArray) = derTlv(0xA0 or tagNo, content)
    private fun derBitString(bytes: ByteArray) = derTlv(0x03, byteArrayOf(0x00) + bytes)
}
