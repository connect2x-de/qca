package de.connect2x.qca.crypto

expect fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initializationVector: ByteArray = SecureRandom.nextBytes(12),
    authenticationData: ByteArray? = null,
): ByteArray

expect fun ByteArray.encryptAes128Ecb(
    key: ByteArray,
): ByteArray

expect fun ByteArray.encryptAes128Cbc(
    key: ByteArray,
    initializationVector: ByteArray = ByteArray(16)
): ByteArray

expect fun ByteArray.decryptAes128Cbc(
    key: ByteArray,
    initializationVector: ByteArray = ByteArray(16)
): ByteArray

expect fun ByteArray.deriveAes128CbcCmac(
    key: ByteArray,
): ByteArray