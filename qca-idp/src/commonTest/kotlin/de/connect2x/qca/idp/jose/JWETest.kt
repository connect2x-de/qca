package de.connect2x.qca.idp.jose

import de.connect2x.qca.crypto.BrainpoolP256r1Key
import de.connect2x.qca.crypto.decodeX962
import io.kotest.assertions.assertSoftly
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import okio.ByteString.Companion.toByteString
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class JWETest {
    @Test
    fun shouldDeriveJWEKey() {
        val peerPublicKey = ("04" +
                "40ba49fcba45c7eeb2261b1be0ebc7c14d6484b9ef8a23b060ebe67f97252bbc" +
                "987ba49df364a0c9926f2b6de1baf46068a13a2c5c9812b2f3451f48b75719ee").hexToByteArray()

        val ephemeralPrivateKey = "a1746e2e69305e90bce385965f82069be49ac9afe190e69f951cb214a8cb9475".hexToByteArray()

        deriveJWEKey(peerPublicKey, BrainpoolP256r1Key(ephemeralPrivateKey)).toHexString() shouldBe
                "d624c6f81b44ce7d26e98841beb79652e9dec79dfd8e2e6f6e706a105d37ec87"
    }

    @Test
    fun shouldEncryptForIdp() {
        val peerPublicKey = ("04" +
                "4178088a425736b88f3a6ab2b7f7e6238c34b1a52c56ce41f53aa61b5f4d98e1" +
                "34bfa20462a67538b5aa530e717f615d0993cfc44ea79619f5d118110edf9241").hexToByteArray()
        val ephemeralKey =
            BrainpoolP256r1Key(privateKey = "a6d5618b5fd8725c26e32e8bcdaa3b17d1013478f4ed1d38f4827a241ef14941".hexToByteArray())
        val initializationVector = "9b28e782248edbd96faa443a"

        val jwe = JWE.encryptForIdp(
            header = JWE.Header(contentType = "JWT"),
            payload = Payload(
                "njwt" to JsonPrimitive("bla")
            ),
            peerPublicKey = peerPublicKey,
            ephemeralKey = ephemeralKey,
            initializationVector = initializationVector.hexToByteArray(),
        )

        val (x, y) = ephemeralKey.publicKey.decodeX962()
            .run { x.toByteString().base64UrlUnpadded() to y.toByteString().base64UrlUnpadded() }
        assertSoftly {
            jwe.header shouldBe JWE.Header(
                "epk" to joseJson.encodeToJsonElement(
                    JWK(
                        "crv" to JsonPrimitive("BP-256"),
                        "x" to JsonPrimitive(x),
                        "y" to JsonPrimitive(y),
                        keyType = "EC"
                    )
                ),
                contentType = "JWT",
                algorithm = "ECDH-ES",
                encryptionAlgorithm = "A256GCM",
            )
            jwe.encryptedKey.size shouldBe 0
            jwe.initializationVector.toHexString() shouldBe initializationVector
            jwe.authenticationTag.toHexString() shouldBe "ab188de186fd159b877c7fa581cd70dd"
        }
    }
}