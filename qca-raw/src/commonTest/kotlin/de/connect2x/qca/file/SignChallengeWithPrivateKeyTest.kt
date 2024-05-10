package de.connect2x.qca.file

import de.connect2x.qca.idp.UserConsent
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.BigIntegers.fromUnsignedByteArray
import org.junit.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.X509EncodedKeySpec

@OptIn(ExperimentalStdlibApi::class)
class SignChallengeWithPrivateKeyTest {
    @Test
    fun shouldSIgn(): Unit = runTest {
        val rawCertificate = "3082036e30820315a00302010202070360769911b38f300a06082a8648ce3d04" +
                "0302308189310b3009060355040613024445311f301d060355040a0c1667656d" +
                "6174696b20476d6248204e4f542d56414c494431383036060355040b0c2f4865" +
                "696c626572756673617573776569732d4341206465722054656c656d6174696b" +
                "696e667261737472756b747572311f301d06035504030c1647454d2e4842412d" +
                "4341353120544553542d4f4e4c59301e170d3232303931343030303030305a17" +
                "0d3237303931333233353935395a308186310b30090603550406130244453177" +
                "301306035504040c0c4e69c3b16f2047c3b46d657a301b060355040513143830" +
                "323736383833313130303030313433343636301b060355042a0c1448616e6e65" +
                "6c6f72652046726569667261752079302606035504030c1f48616e6e656c6f72" +
                "65204e69c3b16f2047c3b46d657a544553542d4f4e4c59305a301406072a8648" +
                "ce3d020106092b2403030208010107034200047236bad453298cc4aabbf434e9" +
                "894ba17c1375ac60195ef520b591e320a41f741ad90704554962330493457e48" +
                "252cb3ce99d598df05c5d87822ecde38fe6b6ba382016630820162300c060355" +
                "1d130101ff04023000301d0603551d250416301406082b060105050703020608" +
                "2b06010505070304301f0603551d230418301680140d3fb09e908221c15782d7" +
                "8fcb8903b4552a4d1f303806082b06010505070101042c302a302806082b0601" +
                "0505073001861c687474703a2f2f656863612e67656d6174696b2e64652f6f63" +
                "73702f302e0603551d2004273025300906072a8214004c044b300c060a2b0601" +
                "040182cd330101300a06082a8214004c048111300e0603551d0f0101ff040403" +
                "020388301d0603551d0e041604145c95a7684d7bac3e33dcffeb4056952c512c" +
                "5c6a307906052b240803030470306ea4283026310b3009060355040613024445" +
                "31173015060355040a0c0e67656d6174696b204265726c696e30423040303e30" +
                "3c300e0c0cc384727a74696e2f41727a74300906072a8214004c041e131f312d" +
                "4842412d546573746b617274652d383833313130303030313433343636300a06" +
                "082a8648ce3d0403020347003044022057556387112936804995279c5f49a7da" +
                "7adc90b8b5d9e63ae0ea9067ec4ea8c202205952e7f546232e77c4adb1c31ee2" +
                "ee5053e357dd53274eeab8076aa08841522c"
        val rawPrivateKey = "308195020100301406072a8648ce3d020106092b2403030208010107047a3078" +
                "02010104204e966d6ecd0ab7fa839314af240c03654ed4d9535f7dd32fc0adfb" +
                "c65c402dcda00b06092b2403030208010107a144034200047236bad453298cc4" +
                "aabbf434e9894ba17c1375ac60195ef520b591e320a41f741ad9070455496233" +
                "0493457e48252cb3ce99d598df05c5d87822ecde38fe6b6b"
        val rawSignature = SignChallengeWithPrivateKey(rawPrivateKey.hexToByteArray())
            .invoke("dino".toByteArray(), UserConsent(mapOf(), mapOf()))

        val certFactory = CertificateFactory.getInstance("X.509")
        val x509 = certFactory.generateCertificate(rawCertificate.hexToByteArray().inputStream())
        val rawPublicKey = x509.publicKey.encoded
        val keyFactory: KeyFactory = KeyFactory.getInstance("EC")
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(rawPublicKey))

        val asn1Signature = DERSequence(
            arrayOf<ASN1Encodable>(
                ASN1Integer(fromUnsignedByteArray(rawSignature.copyOfRange(0, rawSignature.size / 2))),
                ASN1Integer(fromUnsignedByteArray(rawSignature.copyOfRange(rawSignature.size / 2, rawSignature.size)))
            )
        )
        Signature.getInstance("SHA256withECDSA", BouncyCastleProvider()).run {
            initVerify(publicKey)
            update("dino".toByteArray())
            verify(asn1Signature.encoded)
        }
    }
}