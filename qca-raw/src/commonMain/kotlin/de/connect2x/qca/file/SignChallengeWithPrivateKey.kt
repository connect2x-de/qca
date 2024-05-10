package de.connect2x.qca.file

import de.connect2x.qca.idp.SignChallenge
import de.connect2x.qca.idp.UserConsent
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.BigIntegers
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec

class SignChallengeWithPrivateKey(private val rawPrivateKey: ByteArray) : SignChallenge {
    override suspend fun invoke(challenge: ByteArray, userConsent: UserConsent): ByteArray {
        val keyFactory: KeyFactory = KeyFactory.getInstance("EC")
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(rawPrivateKey))
        val asn1Signature = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider())
            .run {
                initSign(privateKey)
                update(challenge)
                sign()
            }.let(::ASN1InputStream)
            .let(ASN1InputStream::readObject)

        check(asn1Signature is ASN1Sequence) { "signature was not ASN1Sequence" }
        val asn1Primitives =
            asn1Signature.toArray().filterIsInstance<ASN1Integer>()
                .map { BigIntegers.asUnsignedByteArray(it.value) }
        check(asn1Primitives.size == 2) { "signature did not contain two ASN1Primitive" }
        return asn1Primitives[0] + asn1Primitives[1]
    }
}