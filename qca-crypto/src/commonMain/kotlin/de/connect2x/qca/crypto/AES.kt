package de.connect2x.qca.crypto

data class EncryptAesGcmResult(
    val ciphertext: ByteArray,
    val initialisationVector: ByteArray,
    val authenticationTag: ByteArray,
)

expect fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initialisationVector: ByteArray = SecureRandom.nextBytes(16),
    authenticationData: ByteArray? = null,
): EncryptAesGcmResult