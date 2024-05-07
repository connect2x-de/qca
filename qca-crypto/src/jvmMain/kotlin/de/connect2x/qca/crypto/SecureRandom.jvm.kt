package de.connect2x.qca.crypto

private val secureRandom by lazy { java.security.SecureRandom() }

actual fun fillRandomBytes(array: ByteArray) = secureRandom.nextBytes(array)