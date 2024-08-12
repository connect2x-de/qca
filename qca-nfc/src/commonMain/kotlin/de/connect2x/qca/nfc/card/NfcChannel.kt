package de.connect2x.qca.nfc.card

import de.connect2x.qca.nfc.card.apdu.CommandApdu
import de.connect2x.qca.nfc.card.apdu.ResponseApdu

interface NfcChannelBase {
    val isExtendedLengthSupported: Boolean
    val maxTransceiveLength: Int
}

interface NfcChannel : NfcChannelBase {
    suspend fun transmit(input: ByteArray): ByteArray
}

internal expect class NfcChannelImpl(nfcCard: NfcCard) : NfcChannel {
    override val isExtendedLengthSupported: Boolean
    override val maxTransceiveLength: Int
    override suspend fun transmit(input: ByteArray): ByteArray
}

internal class NfcChannelTransmitException(message: String?) : Exception(message)

internal suspend fun NfcChannel.transmit(commandApdu: CommandApdu): ResponseApdu {
    val responseBytes = transmit(commandApdu.apduBytes)
    return ResponseApdu(responseBytes, commandApdu.expectedStatus).requireSuccess()
}