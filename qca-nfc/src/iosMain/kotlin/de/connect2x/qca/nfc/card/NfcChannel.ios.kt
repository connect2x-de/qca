package de.connect2x.qca.nfc.card

import de.connect2x.qca.nfc.util.toByteArray
import de.connect2x.qca.nfc.util.toNSData
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import platform.CoreNFC.NFCErrorDomain
import platform.CoreNFC.NFCISO7816APDU
import platform.Foundation.NSError

internal actual class NfcChannelImpl actual constructor(private val nfcCard: NfcCard) : NfcChannel {

    actual override val isExtendedLengthSupported: Boolean = true
    actual override val maxTransceiveLength: Int = 65536


    actual override suspend fun transmit(input: ByteArray): ByteArray = coroutineScope {
        val command = NFCISO7816APDU(input.toNSData())
        val responseChannel = Channel<Pair<NSError?, ByteArray>>()
        nfcCard.tag.sendCommandAPDU(apdu = command) { data, sw1, sw2, error ->
            launch {
                if (error != null) {
                    responseChannel.send(Pair(error, byteArrayOf()))
                } else {
                    val responseData = (data?.toByteArray() ?: byteArrayOf()) + byteArrayOf(sw1.toByte(), sw2.toByte())
                    responseChannel.send(Pair(null, responseData))
                }
            }
        }
        // wait for completion handler call
        val (error, responseBytes) = responseChannel.receive()
        if (error != null) {
            if (error.domain == NFCErrorDomain) {
                // these errors strongly hint at a lost tag
                // NFCReaderError.Code.readerTransceiveErrorTagConnectionLost, readerTransceiveErrorTagResponseError, readerTransceiveErrorTagNotConnected
                if (error.code in arrayOf(100L, 102L, 104L)) {
                    throw NfcTagLostException(message = error.localizedDescription)
                }
            }
            // exception has to be thrown on this thread in order to be caught in the process
            throw NfcChannelTransmitException(message = error.localizedDescription)
        }
        responseBytes
    }
}