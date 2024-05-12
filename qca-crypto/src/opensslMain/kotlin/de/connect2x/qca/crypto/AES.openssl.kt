package de.connect2x.qca.crypto

import kotlinx.cinterop.*
import org.openssl.*

actual fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initialisationVector: ByteArray,
    authenticationData: ByteArray?,
): EncryptAesGcmResult = withFree {
    require(initialisationVector.size == 16) { "initialization vector must have size 16" }
    val cipher = EVP_aes_256_gcm().checkNotNullError().freeAfter(::EVP_CIPHER_free)
    val context = EVP_CIPHER_CTX_new().checkNotNullError().freeAfter(::EVP_CIPHER_CTX_free)
    val cipherText = encryptAes(cipher, context, this@encryptAes256Gcm, key, initialisationVector, authenticationData)
    val authenticationTag = memScoped {
        val output = ByteArray(16)
        output.asUByteArray().usePinned { pinnedOutput ->
            EVP_CIPHER_CTX_ctrl(
                ctx = context,
                type = EVP_CTRL_GCM_GET_TAG,
                arg = 16,
                ptr = pinnedOutput.addressOf(0),
            ).checkError()
        }
        output
    }
    EncryptAesGcmResult(
        ciphertext = cipherText,
        initialisationVector = initialisationVector,
        authenticationTag = authenticationTag
    )
}

private fun encryptAes(
    cipher: CValuesRef<EVP_CIPHER>?,
    context: CValuesRef<EVP_CIPHER_CTX>?,
    plaintext: ByteArray,
    key: ByteArray,
    initialisationVector: ByteArray,
    authenticationData: ByteArray? = null,
): ByteArray {
    key.asUByteArray().usePinned { pinnedKey ->
        initialisationVector.asUByteArray().usePinned { pinnedInitialisationVector ->
            EVP_EncryptInit_ex2(
                ctx = context,
                cipher = cipher,
                key = pinnedKey.addressOf(0),
                iv = pinnedInitialisationVector.addressOf(0),
                params = null
            ).checkError()
        }
    }
    val blockSize = EVP_CIPHER_CTX_get_block_size(context).checkError()
    EVP_CIPHER_CTX_set_padding(context, 0)
    if (authenticationData != null && authenticationData.isNotEmpty()) {
        authenticationData.toUByteArray().usePinned { pinnedAuthenticationData ->
            memScoped {
                EVP_EncryptUpdate(
                    ctx = context,
                    out = null,
                    outl = alloc<IntVar>().ptr,
                    `in` = pinnedAuthenticationData.addressOf(0),
                    inl = authenticationData.size
                ).checkError()
            }
        }
    }
    return (if (plaintext.isNotEmpty()) plaintext.asUByteArray().usePinned { pinnedInput ->
        memScoped {
            val output = ByteArray(plaintext.size + blockSize)
            val outputLength = alloc<IntVar>()
            output.asUByteArray().usePinned { pinnedOutput ->
                EVP_EncryptUpdate(
                    ctx = context,
                    out = pinnedOutput.addressOf(0),
                    outl = outputLength.ptr,
                    `in` = pinnedInput.addressOf(0),
                    inl = plaintext.size
                ).checkError()
            }
            output.wrapSizeTo(outputLength.value)
        }
    } else ByteArray(0)) + memScoped {
        val output = ByteArray(blockSize)
        val outputLength = alloc<IntVar>()
        output.asUByteArray().usePinned { pinnedOutput ->
            EVP_EncryptFinal_ex(
                ctx = context,
                out = pinnedOutput.addressOf(0),
                outl = outputLength.ptr,
            ).checkError()
        }
        output.wrapSizeTo(outputLength.value)
    }
}