package de.connect2x.qca.crypto

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CCRandomGenerateBytes

actual fun fillRandomBytes(array: ByteArray) {
    if (array.isEmpty()) return

    array.usePinned { pinned ->
        checkAppleError(
            CCRandomGenerateBytes(pinned.addressOf(0), array.size.convert())
        )
    }
}