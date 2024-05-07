package de.connect2x.qca.crypto

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.util.BigIntegers

actual class BrainpoolP256r1Key {
    actual val privateKey: ByteArray
    actual val publicKey: ByteArray

    private val ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("BrainpoolP256r1")

    actual constructor() {
        privateKey = SecureRandom.nextBytes(ecNamedCurveParameterSpec.curve.fieldSize / 8)
        publicKey = publicKeyFromPrivateKey(privateKey)
    }

    actual constructor(privateKey: ByteArray) {
        this.privateKey = privateKey
        publicKey = publicKeyFromPrivateKey(privateKey)
    }

    actual constructor(privateKey: ByteArray, publicKey: ByteArray) {
        this.privateKey = privateKey
        this.publicKey = publicKey
    }

    private fun publicKeyFromPrivateKey(privateKey: ByteArray): ByteArray =
        ecNamedCurveParameterSpec.g.multiply(BigIntegers.fromUnsignedByteArray(privateKey))
            .normalize().getEncoded(false)

    /**
     * Compute a shared secret using the given public key.
     * @param peerPublicKey: the public key material to derive a shared secret in conjunction with its own private information.
     * @return The shared secret in raw bytes
     */
    actual fun sharedSecret(peerPublicKey: ByteArray): ByteArray =
        ecNamedCurveParameterSpec.curve
            .decodePoint(peerPublicKey)
            .multiply(BigIntegers.fromUnsignedByteArray(privateKey))
            .normalize()
            .xCoord.encoded
}