package de.connect2x.qca.crypto

fun ByteArray.dropLeadingZeroByte(): ByteArray =
    if (firstOrNull()?.toInt() == 0x00) copyOfRange(1, size)
    else this


fun ByteArray.padWithLeadingZeroes(): ByteArray =
    if (size >= 32) this
    else ByteArray(32 - size) + this