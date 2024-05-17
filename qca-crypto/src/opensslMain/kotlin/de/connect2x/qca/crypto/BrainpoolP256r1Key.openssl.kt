package de.connect2x.qca.crypto

import kotlinx.cinterop.CValuesRef
import org.openssl.*

class ECCurveImpl : ECCurve {
    private val ecGroupFactory: WithFree.() -> CValuesRef<EC_GROUP> =
        { EC_GROUP_new_by_curve_name(NID_brainpoolP256r1).checkNotNullError().freeAfter(::EC_GROUP_free) }

    override val fieldSize: Int
        get() = withFree {
            val ecGroup = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1).checkNotNullError().freeAfter(::EC_GROUP_free)
            (EC_GROUP_get_degree(ecGroup) + 7) / 8
        }

    override fun ecPoint(): ECPoint = withFree {
        val ecGroup = ecGroupFactory()
        val ecPoint = EC_POINT_new(ecGroup).checkNotNullError().freeAfter(::EC_POINT_free)
        EC_POINT_copy(ecPoint, EC_GROUP_get0_generator(ecGroup))
        toECPoint(ecPoint, ecGroup)
    }

    override fun ECPoint.multiply(by: ByteArray): ECPoint = withFree {
        val ecGroup = ecGroupFactory()
        val resultECPoint = EC_POINT_new(ecGroup).checkNotNullError().freeAfter(::EC_POINT_free)
        EC_POINT_mul(
            group = ecGroup,
            r = resultECPoint,
            n = null,
            q = toOpensslECPoint(this@multiply, ecGroup).also { println(it) },
            m = convertToBigNum(by),
            ctx = null
        ).checkError()
        toECPoint(resultECPoint, ecGroup)
    }

    override fun ECPoint.add(by: ECPoint): ECPoint = withFree {
        val ecGroup = ecGroupFactory()
        val resultECPoint = EC_POINT_new(ecGroup).checkNotNullError().freeAfter(::EC_POINT_free)
        EC_POINT_add(
            group = ecGroup,
            r = resultECPoint,
            a = toOpensslECPoint(this@add, ecGroup),
            b = toOpensslECPoint(by, ecGroup),
            ctx = null
        ).checkError()
        toECPoint(resultECPoint, ecGroup)
    }
}

actual fun <T> withBrainpoolP256r1ECPointContext(block: ECCurve.() -> T): T =
    ECCurveImpl().run(block)