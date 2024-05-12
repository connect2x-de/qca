package de.connect2x.qca.crypto

import io.kotest.assertions.assertSoftly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class AESTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val initialisationVector = ByteArray(16) { (it + 1).toByte() }
    private val authenticationData = ByteArray(12) { (it + 2).toByte() }

    @Test
    fun shouldEncryptAes256Gcm() = runTest {
        val encryptAesGcmResult = "hello".encodeToByteArray().encryptAes256Gcm(key, initialisationVector)

        assertSoftly {
            encryptAesGcmResult.ciphertext.toHexString() shouldBe "a623cf5a2f"
            encryptAesGcmResult.authenticationTag.toHexString() shouldBe "be2445a12b81a033ee3035af65ab7762"
            encryptAesGcmResult.initialisationVector.size shouldNotBe 0
        }
    }

    @Test
    fun shouldEncryptAes256GcmWithAuthData() = runTest {
        val encryptAesGcmResult =
            "hello".encodeToByteArray().encryptAes256Gcm(key, initialisationVector, authenticationData)

        assertSoftly {
            encryptAesGcmResult.ciphertext.toHexString() shouldBe "a623cf5a2f"
            encryptAesGcmResult.authenticationTag.toHexString() shouldBe "987a1d3b6e1d6281e1ab10af68c6253c"
            encryptAesGcmResult.initialisationVector.size shouldNotBe 0
        }
    }

    @Test
    fun shouldEncryptAes256GcmEmptyContent() = runTest {
        val encryptAesGcmResult = ByteArray(0).encryptAes256Gcm(key, initialisationVector)

        assertSoftly {
            encryptAesGcmResult.ciphertext.toHexString() shouldBe ""
            encryptAesGcmResult.authenticationTag.toHexString() shouldBe "633814d5f4a5ef461103e41fc1efa71f"
            encryptAesGcmResult.initialisationVector.size shouldNotBe 0
        }
    }
}
