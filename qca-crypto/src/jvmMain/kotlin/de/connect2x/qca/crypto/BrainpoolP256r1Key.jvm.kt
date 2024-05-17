package de.connect2x.qca.crypto

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.util.BigIntegers

class ECCurveImpl : ECCurve {
    private val ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("BrainpoolP256r1")
    override val fieldSize: Int = ecNamedCurveParameterSpec.curve.fieldSize / 8

    override fun ecPoint(): ECPoint = BackingECPoint(ecNamedCurveParameterSpec.g)

    override fun ECPoint.multiply(by: ByteArray): ECPoint =
        toBouncyECPoint(ecNamedCurveParameterSpec.curve)
            .multiply(BigIntegers.fromUnsignedByteArray(by))
            .toECPoint()

    override fun ECPoint.add(by: ECPoint): ECPoint =
        toBouncyECPoint(ecNamedCurveParameterSpec.curve)
            .add(by.toBouncyECPoint(ecNamedCurveParameterSpec.curve))
            .toECPoint()
}

actual fun <T> withBrainpoolP256r1ECPointContext(block: ECCurve.() -> T): T =
    ECCurveImpl().run(block)