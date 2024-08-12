package de.connect2x.qca.nfc.card.apdu

import io.github.oshai.kotlinlogging.KotlinLogging

private val log = KotlinLogging.logger { }

/**
 * APDU Response
 */
class ResponseApdu(apdu: ByteArray, expectedStatus: Map<Int, ResponseStatus>) {
    init {
        require(apdu.size >= 2) { "Response APDU must not have less than 2 bytes (status bytes SW1, SW2)" }
    }

    private val apdu = apdu.copyOf()

    val nr: Int
        get() = apdu.size - 2

    val data: ByteArray
        get() = apdu.copyOfRange(0, apdu.size - 2)

    val sw1: Int
        get() = apdu[apdu.size - 2].toInt() and 0xFF

    val sw2: Int
        get() = apdu[apdu.size - 1].toInt() and 0xFF

    val sw: Int
        get() = sw1 shl 8 or sw2

    val bytes: ByteArray
        get() = apdu.copyOf()

    val status: ResponseStatus = expectedStatus[sw] ?: ResponseStatus.UNKNOWN_STATUS

    fun requireSuccess(): ResponseApdu {
        if (status != ResponseStatus.SUCCESS) {
            log.error { "nfc card response status not successful: $status" }
            throw ResponseException(this.status)
        }
        return this
    }
}

internal class ResponseException(val responseStatus: ResponseStatus) : Exception()