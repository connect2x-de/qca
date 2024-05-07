package de.connect2x.qca.crypto

fun encodeX962(x: ByteArray, y: ByteArray): ByteArray =
    byteArrayOf(0x04) + x.dropLeadingZeroByte().padWithLeadingZeroes() + y.dropLeadingZeroByte().padWithLeadingZeroes()

internal fun ByteArray.dropLeadingZeroByte(): ByteArray =
    if (firstOrNull()?.toInt() == 0x00) copyOfRange(1, size)
    else this


internal fun ByteArray.padWithLeadingZeroes(): ByteArray =
    if (size >= 32) this
    else ByteArray(32 - size) + this

/**
 * Decodes an ECPoint from byte array (of the form {0x04 || x-bytes [] || y byte []}).
 * Prime field p is taken from the passed curve.
 */
data class ECPoint(
    val x: ByteArray,
    val y: ByteArray,
)

fun ECPoint.encodeX962(): ByteArray = de.connect2x.qca.crypto.encodeX962(x, y)

fun ByteArray.decodeX962(): ECPoint =
    if (this[0] != 0x04.toByte()) {
        throw IllegalArgumentException("Found no uncompressed point!")
    } else {
        val pointLength = (size - 1) / 2
        ECPoint(
            x = copyOfRange(1, pointLength + 1),
            y = copyOfRange(pointLength + 1, size)
        )
    }