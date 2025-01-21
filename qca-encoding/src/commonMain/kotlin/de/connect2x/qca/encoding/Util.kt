package de.connect2x.qca.encoding

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

internal fun ByteArray.toByte(): Byte = get(0)

internal fun ByteArray.toUByte(): UByte = get(0).toUByte()

internal fun ByteArray.toShort(): Short =
    get(0).toULong().shl(8)
        .or(get(1).toULong())
        .toShort()

internal fun ByteArray.toUShort(): UShort =
    get(0).toULong().shl(8)
        .or(get(1).toULong())
        .toUShort()

internal fun ByteArray.toInt(): Int =
    get(0).toULong().shl(24)
        .or(get(1).toULong().shl(16))
        .or(get(2).toULong().shl(8))
        .or(get(3).toULong())
        .toInt()

internal fun ByteArray.toUInt(): UInt =
    get(0).toULong().shl(24)
        .or(get(1).toULong().shl(16))
        .or(get(2).toULong().shl(8))
        .or(get(3).toULong())
        .toUInt()

internal fun ByteArray.toLong(): Long =
    get(0).toULong().shl(56)
        .or(get(1).toULong().shl(48))
        .or(get(2).toULong().shl(40))
        .or(get(3).toULong().shl(32))
        .or(get(4).toULong().shl(24))
        .or(get(5).toULong().shl(16))
        .or(get(6).toULong().shl(8))
        .or(get(7).toULong())
        .toLong()

internal fun ByteArray.toULong(): ULong =
    get(0).toULong().shl(56)
        .or(get(1).toULong().shl(48))
        .or(get(2).toULong().shl(40))
        .or(get(3).toULong().shl(32))
        .or(get(4).toULong().shl(24))
        .or(get(5).toULong().shl(16))
        .or(get(6).toULong().shl(8))
        .or(get(7).toULong())

internal fun ByteArray.toBigInteger(): BigInteger =
    BigInteger.fromByteArray(this, Sign.POSITIVE)

internal fun Byte.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        toByte()
    )
}

internal fun UByte.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        toByte()
    )
}

internal fun Short.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        shr(8).toByte(),
        toByte()
    )
}

internal fun UShort.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        shr(8).toByte(),
        toByte()
    )
}

internal fun Int.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        shr(24).toByte(),
        shr(16).toByte(),
        shr(8).toByte(),
        toByte()
    )
}

internal fun UInt.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        shr(24).toByte(),
        shr(16).toByte(),
        shr(8).toByte(),
        toByte()
    )
}

internal fun Long.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        shr(56).toByte(),
        shr(48).toByte(),
        shr(40).toByte(),
        shr(32).toByte(),
        shr(24).toByte(),
        shr(16).toByte(),
        shr(8).toByte(),
        toByte()
    )
}

internal fun ULong.toByteArray(): ByteArray = with(toULong()) {
    byteArrayOf(
        shr(56).toByte(),
        shr(48).toByte(),
        shr(40).toByte(),
        shr(32).toByte(),
        shr(24).toByte(),
        shr(16).toByte(),
        shr(8).toByte(),
        toByte()
    )
}
