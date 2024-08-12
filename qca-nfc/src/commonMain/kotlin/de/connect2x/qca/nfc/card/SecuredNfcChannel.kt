package de.connect2x.qca.nfc.card

import de.connect2x.qca.nfc.card.apdu.CommandApdu
import de.connect2x.qca.nfc.card.apdu.ResponseApdu

interface SecuredNfcChannel : NfcChannelBase {
    suspend fun transmit(commandApdu: CommandApdu): ResponseApdu
}