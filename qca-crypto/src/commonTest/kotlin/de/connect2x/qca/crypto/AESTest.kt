package de.connect2x.qca.crypto

import io.kotest.matchers.shouldBe
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class AESTest {
    private val key16 = ByteArray(16) { (it + 1).toByte() }
    private val key32 = ByteArray(32) { (it + 1).toByte() }
    private val initialisationVector12 = ByteArray(12) { (it + 1).toByte() }
    private val initialisationVector16 = ByteArray(16) { (it + 1).toByte() }
    private val authenticationData = ByteArray(12) { (it + 2).toByte() }

    @Test
    fun shouldEncryptAes256Gcm() = runTest {
        "hello".encodeToByteArray().encryptAes256Gcm(key32, initialisationVector12).toHexString() shouldBe
                "c64bc0f15f" + "dd3d884fa4ba8cff4339f2b5e3cf64c2"
    }

    @Test
    fun shouldEncryptAes256GcmWithAuthData() = runTest {
        "hello".encodeToByteArray().encryptAes256Gcm(key32, initialisationVector12, authenticationData)
            .toHexString() shouldBe
                "c64bc0f15f" + "fb63d0d5e1264e4d4ca2d7b5eea2369c"
    }

    @Test
    fun shouldEncryptAes256GcmEmptyContent() = runTest {
        ByteArray(0).encryptAes256Gcm(key32, initialisationVector12).toHexString() shouldBe
                "7737397e14746df371992992a1791250"
    }

    @Test
    fun shouldEncryptAes128Ecb() {
        "hello-dino-dino!".encodeToByteArray().encryptAes128Ecb(key16).toHexString() shouldBe
                "76d44b9178ebd72397b463b55003e5e8"
    }

    @Test
    fun shouldEncryptAes128Cbc() {
        println("hello-dino-dino!".encodeToByteArray().toHexString())
        println(key16.toHexString())
        println(initialisationVector16.toHexString())
        "hello-dino-dino!".encodeToByteArray().encryptAes128Cbc(key16, initialisationVector16).toHexString() shouldBe
                "606815850ffe46f309883c5c47862cfb"
    }

    @Test
    fun shouldDecryptAes128Cbc() {
        "606815850ffe46f309883c5c47862cfb".hexToByteArray().decryptAes128Cbc(key16, initialisationVector16)
            .decodeToString() shouldBe
                "hello-dino-dino!"
    }

    @Test
    fun shouldDeriveAes128CbcCmac() {
        "7f494f060a04007f0007020204020286410448af0098ca2ee3c753332daabc14073a7f1583751d119736d0922d684cc39868932392287208541d62fd852d3989f5335c00f19c6c47b621af03893be4d028b2".hexToByteArray()
            .deriveAes128CbcCmac("82e050473a15fdff75d57d004a97a5fa".hexToByteArray()).toHexString() shouldBe
                "314e51b53252a366"
    }
}
