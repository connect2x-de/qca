package de.connect2x.qca.nfc.card

import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import io.github.oshai.kotlinlogging.KotlinLogging

private val log = KotlinLogging.logger { }

private const val ISO_DEP_TIMEOUT = 2500

internal actual class NfcChannelImpl actual constructor(nfcCard: NfcCard) : NfcChannel {
    private val isoDep: IsoDep
    actual override val isExtendedLengthSupported: Boolean
    actual override val maxTransceiveLength: Int

    init {
        isoDep = IsoDep.get(nfcCard.tag).apply {
            log.debug { "Try isoDep connect ..." }
            connect()
            log.debug { "... isoDep connected" }
            log.debug { "isoDep maxTransceiveLength: $maxTransceiveLength" }
        }
        isoDep.timeout = ISO_DEP_TIMEOUT
        maxTransceiveLength = isoDep.maxTransceiveLength
        isExtendedLengthSupported = isoDep.isExtendedLengthApduSupported
    }

    actual override suspend fun transmit(input: ByteArray): ByteArray = try {
        isoDep.transceive(input)
    } catch (tagLostException: TagLostException) {
        throw NfcTagLostException(tagLostException.message, tagLostException)
    }
}