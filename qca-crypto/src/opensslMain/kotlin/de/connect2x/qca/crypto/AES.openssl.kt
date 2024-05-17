package de.connect2x.qca.crypto

import kotlinx.cinterop.*
import org.openssl.*

actual fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initializationVector: ByteArray,
    authenticationData: ByteArray?,
): ByteArray = withFree {
    val cipher = EVP_aes_256_gcm().checkNotNullError().freeAfter(::EVP_CIPHER_free)
    val context = EVP_CIPHER_CTX_new().checkNotNullError().freeAfter(::EVP_CIPHER_CTX_free)
    val cipherText = encryptAes(
        cipher = cipher,
        context = context,
        plaintext = this@encryptAes256Gcm,
        key = key,
        initializationVector = initializationVector,
        authenticationData = authenticationData
    )
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
    cipherText + authenticationTag
}

actual fun ByteArray.encryptAes128Ecb(
    key: ByteArray,
): ByteArray = withFree {
    val cipher = EVP_aes_128_ecb().checkNotNullError().freeAfter(::EVP_CIPHER_free)
    val context = EVP_CIPHER_CTX_new().checkNotNullError().freeAfter(::EVP_CIPHER_CTX_free)
    encryptAes(
        cipher = cipher,
        context = context,
        plaintext = this@encryptAes128Ecb,
        key = key,
    )
}

actual fun ByteArray.encryptAes128Cbc(
    key: ByteArray,
    initializationVector: ByteArray,
): ByteArray = withFree {
    val cipher = EVP_aes_128_cbc().checkNotNullError().freeAfter(::EVP_CIPHER_free)
    val context = EVP_CIPHER_CTX_new().checkNotNullError().freeAfter(::EVP_CIPHER_CTX_free)
    encryptAes(
        cipher = cipher,
        context = context,
        plaintext = this@encryptAes128Cbc,
        key = key,
        initializationVector = initializationVector,
    )
}

private fun encryptAes(
    cipher: CValuesRef<EVP_CIPHER>?,
    context: CValuesRef<EVP_CIPHER_CTX>?,
    plaintext: ByteArray,
    key: ByteArray,
    initializationVector: ByteArray? = null,
    authenticationData: ByteArray? = null,
): ByteArray {
    key.asUByteArray().usePinned { pinnedKey ->
        initializationVector?.asUByteArray()?.usePinned { pinnedInitialisationVector ->
            EVP_EncryptInit_ex2(
                ctx = context,
                cipher = cipher,
                key = pinnedKey.addressOf(0),
                iv = pinnedInitialisationVector.addressOf(0),
                params = null
            ).checkError()
        } ?: EVP_EncryptInit_ex2(
            ctx = context,
            cipher = cipher,
            key = pinnedKey.addressOf(0),
            iv = null,
            params = null
        ).checkError()
    }
    val blockSize = EVP_CIPHER_CTX_get_block_size(context).checkError()
    EVP_CIPHER_CTX_set_padding(context, 0)
    if (authenticationData != null && authenticationData.isNotEmpty()) {
        authenticationData.asUByteArray().usePinned { pinnedAuthenticationData ->
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

actual fun ByteArray.decryptAes128Cbc(
    key: ByteArray,
    initializationVector: ByteArray,
): ByteArray = withFree {
    val cipher = EVP_aes_128_cbc().checkNotNullError().freeAfter(::EVP_CIPHER_free)
    val context = EVP_CIPHER_CTX_new().checkNotNullError().freeAfter(::EVP_CIPHER_CTX_free)
    check(key.isNotEmpty()) { "key must not be empty" }
    check(initializationVector.isNotEmpty()) { "initialisationVector must not be empty" }
    key.asUByteArray().usePinned { pinnedKey ->
        initializationVector.asUByteArray().usePinned { pinnedInitializationVector ->
            EVP_DecryptInit(
                ctx = context,
                cipher = cipher,
                key = pinnedKey.addressOf(0),
                iv = pinnedInitializationVector.addressOf(0),
            ).checkError()
        }
    }
    val blockSize = EVP_CIPHER_CTX_get_block_size(context).checkError()
    EVP_CIPHER_CTX_set_padding(context, 0)
    val decryptedOutput = this@decryptAes128Cbc.asUByteArray().usePinned { pinnedInput ->
        memScoped {
            val output = ByteArray(this@decryptAes128Cbc.size + blockSize)
            val outputLength = alloc<IntVar>()
            output.asUByteArray().usePinned { pinnedOutput ->
                EVP_DecryptUpdate(
                    ctx = context,
                    out = pinnedOutput.addressOf(0),
                    outl = outputLength.ptr,
                    `in` = pinnedInput.addressOf(0),
                    inl = this@decryptAes128Cbc.size
                ).checkError()
            }
            output.wrapSizeTo(outputLength.value)
        }
    }
    val decryptedFinalOutput = memScoped {
        val output = ByteArray(blockSize)
        val outputLength = alloc<IntVar>()
        output.asUByteArray().usePinned { pinnedOutput ->
            EVP_DecryptFinal(
                ctx = context,
                outm = pinnedOutput.addressOf(0),
                outl = outputLength.ptr
            ).checkError()
        }
        output.wrapSizeTo(outputLength.value)
    }
    return (decryptedOutput + decryptedFinalOutput)
}

@OptIn(ExperimentalForeignApi::class)
actual fun ByteArray.deriveAes128CbcCmac(
    key: ByteArray,
): ByteArray {
    val byteCount = 16
    require(key.size == byteCount) { "Key length invalid for CMAC calculation" }
    val macToken = ByteArray(byteCount)
    memScoped {
        val outputLength = alloc<ULongVar>()
        key.asUByteArray().usePinned { pinnedKey ->
            this@deriveAes128CbcCmac.asUByteArray().usePinned { pinnedData ->
                macToken.asUByteArray().usePinned { pinnedMacToken ->
                    EVP_Q_mac(
                        null,
                        "cmac",
                        null,
                        "aes-128-cbc",
                        null,
                        pinnedKey.addressOf(0),
                        byteCount.toULong(),
                        pinnedData.addressOf(0),
                        this@deriveAes128CbcCmac.size.toULong(),
                        pinnedMacToken.addressOf(0),
                        byteCount.toULong(),
                        outputLength.ptr
                    ).checkNotNullError()
                }
            }
        }
    }
    // return prefix
    return macToken.copyOfRange(0, 8)
}