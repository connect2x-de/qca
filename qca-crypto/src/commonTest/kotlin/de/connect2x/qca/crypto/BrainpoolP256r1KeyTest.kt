package de.connect2x.qca.crypto

import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class BrainpoolP256r1KeyTest {

    @Test
    fun testBrainPoolKeyCreation() {
        val first = BrainpoolP256r1Key()
        val second = BrainpoolP256r1Key(first.privateKey)
        val third = BrainpoolP256r1Key(first.privateKey, first.publicKey)

        first.privateKey.size shouldBe 32
        first.publicKey.size shouldBe 65
        first.privateKey.toHexString().shouldNotContain("00000000000000000")
        first.publicKey.toHexString().shouldNotContain("00000000000000000")
        second.privateKey.toHexString() shouldBe first.privateKey.toHexString()
        second.publicKey.toHexString() shouldBe first.publicKey.toHexString()
        third.privateKey.toHexString() shouldBe first.privateKey.toHexString()
        third.publicKey.toHexString() shouldBe first.publicKey.toHexString()

        BrainpoolP256r1Key("6d59688a7e1893d430601b73affa0289cc318ca0e2fcb6fbe12f6a0949c1504c".hexToByteArray())
            .publicKey.toHexString() shouldBe "04" +
                "5dd1c112a6ab210b817ae7e472ddc52948680842112ac31873f272cc5769d005" +
                "5b29cec83f0a32ca9ab2a4eebb8982133c27e72ee7c5a16a8e7d4d7c499591cf"

        BrainpoolP256r1Key("fd59688a7e1893d430601b73affa0289cc318ca0e2fcb6fbe12f6a0949c1504c".hexToByteArray())
            .publicKey.toHexString() shouldBe "04" + "" +
                "9fbfbe96b1a6cb01c65a66aca9be6da5d22dc65c7ac4639903a10d0863c5a4e1" +
                "232108d6bc9cb7aee7828486cf10346cc1e5db87799f99873ed89226190386ef"
    }

    @Test
    fun testSharedSecret() {
        val key =
            BrainpoolP256r1Key("0D7DFFAC3558C4C3C075A0479F4C3A4864DBD8E686CDB154DD0BDD0BA7CE4D51".hexToByteArray())
        val publicKey = ("04" +
                "5CAC41779F548CBE714A08CBCEB40F616B5EFDD59DD3345802027DCB0C3FB02B" +
                "20DC7A458B7744102DE98D350D4399FEC0F8CC5CCE50317A2CEE3CB418A4DA41").hexToByteArray()
        key.sharedSecret(publicKey)
            .toHexString() shouldBe "3647d88e5bc89831b64a28997a0967cd732795c2cdfae9f47d7eb126c31c36a5"
    }

    @Test
    fun testSameSharedSecret() {
        repeat(100) {
            val key1 = BrainpoolP256r1Key()
            val key2 = BrainpoolP256r1Key()
            key1.sharedSecret(key2.publicKey).toHexString() shouldBe key2.sharedSecret(key1.publicKey).toHexString()
        }
    }

    @Test
    fun testPaceMapNonce() {
        val privateKey = "0d7dffac3558c4c3c075a0479f4c3a4864dbd8e686cdb154dd0bdd0ba7ce4d51".hexToByteArray()
        val key = BrainpoolP256r1Key(privateKey)
        val nonce = "a44248628b8e8b94072ef3843c56e844".hexToByteArray()
        val peerPublicKey = ("04" +
                "5cac41779f548cbe714a08cbceb40f616b5efdd59dd3345802027dcb0c3fb02b" +
                "20dc7a458b7744102de98d350d4399fec0f8cc5cce50317a2cee3cb418a4da41").hexToByteArray()

        val ephemeralPrivateKey = "4c164b01d17b7c097b3640af1ebce0c88ed4b57738803872eec3261ebb9a89e7".hexToByteArray()
        key.paceMapNonce(
            peerPublicKey = peerPublicKey,
            nonce = nonce,
            ephemeralKey = BrainpoolP256r1Key(ephemeralPrivateKey)
        ).toHexString() shouldBe
                "04" +
                "a1d37688f62647e4b7cceb64881142eeec48fcf148ba2b518e3246166ef8495c" +
                "81d0644a59dd6927e7492a4bd52926957450beded208b2e616d03d9504f9fe12"
    }
}