package de.connect2x.qca.nfc.card

class NfcAuthenticationFailedException(val reason: NfcAuthenticationFailedReason, cause: Throwable? = null) :
    IllegalStateException(reason.toString(), cause)

sealed interface NfcAuthenticationFailedReason {
    data object PinNotUsable : NfcAuthenticationFailedReason
    data object PinLocked : NfcAuthenticationFailedReason
    data class PinWrong(val retriesLeft: Int) : NfcAuthenticationFailedReason
    data class Unknown(val reason: String) : NfcAuthenticationFailedReason
    data object CanWrong : NfcAuthenticationFailedReason
}