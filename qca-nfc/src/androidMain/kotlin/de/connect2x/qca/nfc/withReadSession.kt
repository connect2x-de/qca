package de.connect2x.qca.nfc

import android.app.Activity
import android.nfc.NfcAdapter
import android.os.Bundle
import de.connect2x.qca.nfc.card.NfcCard
import de.connect2x.qca.nfc.card.NfcCardFactory
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel

suspend fun <T> withReadSession(activity: Activity, block: suspend (NfcCardFactory) -> T): T =
    withReadSession(
        activity = activity,
        nfcAdapter = checkNotNull(NfcAdapter.getDefaultAdapter(activity.applicationContext)) { "no NfcAdapter found" },
        block = block
    )

suspend fun <T> withReadSession(activity: Activity, nfcAdapter: NfcAdapter, block: suspend (NfcCardFactory) -> T): T {
    val nfcCards = Channel<NfcCard>(1, BufferOverflow.DROP_OLDEST)
    nfcAdapter.enableReaderMode(
        activity,
        { nfcCards.trySend(NfcCard(it)) },
        NfcAdapter.FLAG_READER_NFC_A
                or NfcAdapter.FLAG_READER_NFC_B
                or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
        Bundle(),
    )
    return try {
        block { nfcCards.receive() }
    } finally {
        nfcAdapter.disableReaderMode(activity)
    }
}