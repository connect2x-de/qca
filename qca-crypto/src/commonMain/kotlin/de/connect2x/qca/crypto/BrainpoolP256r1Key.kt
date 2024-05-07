package de.connect2x.qca.crypto

expect class BrainpoolP256r1Key {
    val privateKey: ByteArray
    val publicKey: ByteArray

    constructor()

    constructor(privateKey: ByteArray)

    constructor(privateKey: ByteArray, publicKey: ByteArray)

    /**
     * Compute a shared secret using the given public key.
     * @param peerPublicKey: the public key material (X9.62 encoded) to derive a shared secret in conjunction with its own private information.
     * @return The shared secret in raw bytes
     */
    fun sharedSecret(peerPublicKey: ByteArray): ByteArray
}