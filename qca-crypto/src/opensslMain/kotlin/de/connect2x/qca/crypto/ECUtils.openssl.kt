package de.connect2x.qca.crypto

import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import org.openssl.*

// we currently don't have a BackingECPoint as in JVM, because we need to manage memory manually (free)

fun WithFree.toOpensslECPoint(ecPoint: ECPoint, ecGroup: CValuesRef<EC_GROUP>): CValuesRef<EC_POINT> {
    val opensslEcPoint = EC_POINT_new(ecGroup).checkNotNullError().freeAfter(::EC_POINT_free)
    EC_POINT_set_affine_coordinates(
        group = ecGroup,
        p = opensslEcPoint,
        x = convertToBigNum(ecPoint.x),
        y = convertToBigNum(ecPoint.y),
        ctx = null,
    ).checkError()
    return opensslEcPoint
}

fun WithFree.toECPoint(ecPoint: CValuesRef<EC_POINT>, ecGroup: CValuesRef<EC_GROUP>): ECPoint {
    val x = BN_new().checkNotNullError().freeAfter(::BN_free)
    val y = BN_new().checkNotNullError().freeAfter(::BN_free)
    
    EC_POINT_get_affine_coordinates(
        group = ecGroup,
        p = ecPoint,
        x = x,
        y = y,
        ctx = null,
    )
    return ECPointImpl(
        x.convertToByteArray(),
        y.convertToByteArray(),
    )
}

fun WithFree.convertToBigNum(value: ByteArray): CValuesRef<BIGNUM> =
    value.asUByteArray().usePinned { pinnedValue ->
        BN_bin2bn(
            s = pinnedValue.addressOf(0),
            len = value.size,
            ret = null
        ).checkNotNullError().freeAfter(::BN_free)
    }

private fun CValuesRef<BIGNUM>.convertToByteArray(): ByteArray {
    val byteArray = ByteArray((BN_num_bits(this) + 7) / 8)
    byteArray.asUByteArray().usePinned { pinnedByteArray ->
        BN_bn2bin(this, pinnedByteArray.addressOf(0)).checkError()
    }
    return byteArray
}
