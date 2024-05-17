package de.connect2x.qca.crypto

import org.bouncycastle.util.BigIntegers
import org.bouncycastle.math.ec.ECCurve as BouncyECCurve
import org.bouncycastle.math.ec.ECPoint as BouncyECPoint

class BackingECPoint(val base: BouncyECPoint) : ECPoint {
    override val x: ByteArray
        get() = base.normalize().xCoord.encoded
    override val y: ByteArray
        get() = base.normalize().yCoord.encoded

    override fun encodeX962(): ByteArray = base.getEncoded(false)
}

fun ECPoint.toBouncyECPoint(curve: BouncyECCurve): BouncyECPoint =
    if (this is BackingECPoint) base
    else curve.createPoint(BigIntegers.fromUnsignedByteArray(x), BigIntegers.fromUnsignedByteArray(y))

fun BouncyECPoint.toECPoint(): ECPoint = BackingECPoint(this)