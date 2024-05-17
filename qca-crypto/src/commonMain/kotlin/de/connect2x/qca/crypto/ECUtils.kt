package de.connect2x.qca.crypto

interface ECPoint {
    val x: ByteArray
    val y: ByteArray

    fun encodeX962(): ByteArray
}

class ECPointImpl(
    override val x: ByteArray,
    override val y: ByteArray,
) : ECPoint {
    override fun encodeX962(): ByteArray =
        byteArrayOf(0x04) + x.dropLeadingZeroByte().padWithLeadingZeroes() + y.dropLeadingZeroByte()
            .padWithLeadingZeroes()

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String =
        "ECPointImpl(x=${x.toHexString()}, y=${y.toHexString()})"
}

fun ByteArray.decodeX962(): ECPoint =
    if (this[0] != 0x04.toByte()) {
        throw IllegalArgumentException("Found no uncompressed point!")
    } else {
        val pointLength = (size - 1) / 2
        ECPointImpl(
            x = copyOfRange(1, pointLength + 1),
            y = copyOfRange(pointLength + 1, size)
        )
    }

interface ECCurve {
    val fieldSize: Int
    fun ecPoint(): ECPoint
    fun ECPoint.multiply(by: ByteArray): ECPoint
    fun ECPoint.add(by: ECPoint): ECPoint
}