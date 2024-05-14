package de.connect2x.qca.crypto

import io.kotest.assertions.assertSoftly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class AESTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val initialisationVector = ByteArray(12) { (it + 1).toByte() }
    private val authenticationData = ByteArray(12) { (it + 2).toByte() }

    @Test
    fun shouldEncryptAes256Gcm() = runTest {
        val encryptAesGcmResult = "hello".encodeToByteArray().encryptAes256Gcm(key, initialisationVector)

        assertSoftly {
            encryptAesGcmResult.ciphertext.toHexString() shouldBe "c64bc0f15f"
            encryptAesGcmResult.authenticationTag.toHexString() shouldBe "dd3d884fa4ba8cff4339f2b5e3cf64c2"
            encryptAesGcmResult.initialisationVector.size shouldNotBe 0
        }
    }

    @Test
    fun shouldEncryptAes256GcmWithAuthData() = runTest {
        val encryptAesGcmResult =
            "hello".encodeToByteArray().encryptAes256Gcm(key, initialisationVector, authenticationData)

        assertSoftly {
            encryptAesGcmResult.ciphertext.toHexString() shouldBe "c64bc0f15f"
            encryptAesGcmResult.authenticationTag.toHexString() shouldBe "fb63d0d5e1264e4d4ca2d7b5eea2369c"
            encryptAesGcmResult.initialisationVector.size shouldNotBe 0
        }
    }

    @Test
    fun shouldEncryptAes256GcmEmptyContent() = runTest {
        val encryptAesGcmResult = ByteArray(0).encryptAes256Gcm(key, initialisationVector)

        assertSoftly {
            encryptAesGcmResult.ciphertext.toHexString() shouldBe ""
            encryptAesGcmResult.authenticationTag.toHexString() shouldBe "7737397e14746df371992992a1791250"
            encryptAesGcmResult.initialisationVector.size shouldNotBe 0
        }
    }
}
