package de.connect2x.qca.crypto

import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initializationVector: ByteArray,
    authenticationData: ByteArray?,
): EncryptAesGcmResult {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec: Key = SecretKeySpec(key, "AES")
    val gcmSpec = GCMParameterSpec(128, initializationVector)

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

    if (authenticationData != null && authenticationData.isNotEmpty())
        cipher.updateAAD(authenticationData)
    val cipherTextAndAuthenticationTag = cipher.doFinal(this)

    return EncryptAesGcmResult(
        ciphertext = cipherTextAndAuthenticationTag
            .copyOfRange(0, cipherTextAndAuthenticationTag.size - 16),
        initialisationVector = initializationVector,
        authenticationTag = cipherTextAndAuthenticationTag
            .copyOfRange(cipherTextAndAuthenticationTag.size - 16, cipherTextAndAuthenticationTag.size),
    )
}