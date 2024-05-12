package de.connect2x.qca.crypto

import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initialisationVector: ByteArray,
    authenticationData: ByteArray?,
): EncryptAesGcmResult {
    require(initialisationVector.size == 16) { "initialization vector must have size 12" }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val keySpec: Key = SecretKeySpec(key, "AES")
    val gcmSpec = GCMParameterSpec(128, initialisationVector)

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

    if (authenticationData != null && authenticationData.isNotEmpty())
        cipher.updateAAD(authenticationData)
    val cipherTextAndAuthenticationTag = cipher.doFinal(this)

    return EncryptAesGcmResult(
        ciphertext = cipherTextAndAuthenticationTag
            .copyOfRange(0, cipherTextAndAuthenticationTag.size - 16),
        initialisationVector = initialisationVector,
        authenticationTag = cipherTextAndAuthenticationTag
            .copyOfRange(cipherTextAndAuthenticationTag.size - 16, cipherTextAndAuthenticationTag.size),
    )
}