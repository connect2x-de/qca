package de.connect2x.qca.nfc.card

import de.connect2x.qca.nfc.card.pace.establishPaceSecuredNfcChannel
import io.github.oshai.kotlinlogging.KotlinLogging

private val log = KotlinLogging.logger { }

expect class NfcCard

fun interface NfcCardFactory {
    suspend operator fun invoke(): NfcCard
}

suspend fun <T> useNfcCardSecured(
    retries: Int = 10,
    nfcCardFactory: NfcCardFactory,
    can: String,
    block: suspend SecuredNfcChannel.() -> T,
): T {
    repeat(retries - 1) {
        try {
            val nfcCard = nfcCardFactory()
            val nfcCardChannel = NfcChannelImpl(nfcCard)
            val secureChannel = nfcCardChannel.establishPaceSecuredNfcChannel(can = can)
            return block(secureChannel)
        } catch (e: NfcTagLostException) {
            log.warn { "Tag lost - will retry." }
        }
    }
    // last attempt (may throw TagLostException):
    val nfcCard = nfcCardFactory()
    val nfcCardChannel = NfcChannelImpl(nfcCard)
    val secureChannel = nfcCardChannel.establishPaceSecuredNfcChannel(can = can)
    return block(secureChannel)
}