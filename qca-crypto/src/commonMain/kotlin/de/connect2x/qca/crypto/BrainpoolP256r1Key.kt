package de.connect2x.qca.crypto

class BrainpoolP256r1Key {
    val privateKey: ByteArray
    val publicKey: ByteArray

    constructor() {
        privateKey = SecureRandom.nextBytes(withBrainpoolP256r1ECPointContext { fieldSize })
        publicKey = publicKeyFromPrivateKey(privateKey)
    }

    constructor(privateKey: ByteArray) {
        this.privateKey = privateKey
        publicKey = publicKeyFromPrivateKey(privateKey)
    }

    constructor(privateKey: ByteArray, publicKey: ByteArray) {
        this.privateKey = privateKey
        this.publicKey = publicKey
    }

    private fun publicKeyFromPrivateKey(privateKey: ByteArray): ByteArray = withBrainpoolP256r1ECPointContext {
        ecPoint()
            .multiply(privateKey)
            .encodeX962()
    }

    /**
     * Compute a shared secret using the given public key.
     * @param peerPublicKey: the public key material (X9.62 encoded) to derive a shared secret in conjunction with its own private information.
     * @return The shared secret in raw bytes
     */
    fun sharedSecret(peerPublicKey: ByteArray): ByteArray = withBrainpoolP256r1ECPointContext {
        peerPublicKey.decodeX962()
            .multiply(privateKey)
            .x
    }

    /**
     * @param nonce Plain nonce queried from the peer entity
     * @param peerPublicKey First ephemeral public key received from the peer entity
     * @param ephemeralKeyGenerator function to generate a key (pair), mainly for testing purposes
     * @return Derived ephemeral shared public key and the ephemeral private key pair
     */
    fun paceMapNonce(
        nonce: ByteArray,
        peerPublicKey: ByteArray,
        ephemeralKeyGenerator: () -> BrainpoolP256r1Key = { BrainpoolP256r1Key() }
    ): Pair<ByteArray, BrainpoolP256r1Key> = withBrainpoolP256r1ECPointContext {
        val noncePublicKey = ecPoint().multiply(nonce)
        val sharedSecret = peerPublicKey.decodeX962().multiply(privateKey)

        val sharedPoint = noncePublicKey.add(sharedSecret)

        val ephemeralKey = ephemeralKeyGenerator()
        val ephemeralSharedPublicKey =
            sharedPoint.multiply(ephemeralKey.privateKey)
                .encodeX962()
        Pair(ephemeralSharedPublicKey, ephemeralKey)
    }
}

expect fun <T> withBrainpoolP256r1ECPointContext(block: ECCurve.() -> T): T