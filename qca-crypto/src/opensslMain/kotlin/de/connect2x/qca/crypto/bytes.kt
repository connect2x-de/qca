package de.connect2x.qca.crypto

internal fun ByteArray.wrapSizeTo(expectedSize: Int): ByteArray = when (size) {
    expectedSize -> this
    else -> copyOf(expectedSize)
}