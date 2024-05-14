package de.connect2x.qca.crypto

data class EncryptAesGcmResult(
    val ciphertext: ByteArray,
    val initialisationVector: ByteArray,
    val authenticationTag: ByteArray,
)

expect fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initializationVector: ByteArray = SecureRandom.nextBytes(12),
    authenticationData: ByteArray? = null,
): EncryptAesGcmResult