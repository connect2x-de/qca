package de.connect2x.qca.nfc.card

class NfcUnlockFailedException(val reason: NfcUnlockFailedReason, cause: Throwable? = null) :
    IllegalStateException(reason.toString(), cause)

sealed interface NfcUnlockFailedReason {
    data object PukBlocked : NfcUnlockFailedReason
    data class PukRetriesLeft(val retriesLeft: Int) : NfcUnlockFailedReason
    data object InvalidLength : NfcUnlockFailedReason
    data object SecurityStatusNotSatisfied : NfcUnlockFailedReason
    data object UserNotAuthenticated : NfcUnlockFailedReason
}