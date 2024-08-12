package de.connect2x.qca.crypto

import java.security.MessageDigest

actual fun ByteArray.sha256(): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(this)
    return digest.digest()
}