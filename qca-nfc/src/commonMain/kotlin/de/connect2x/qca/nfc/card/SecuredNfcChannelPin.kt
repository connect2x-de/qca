package de.connect2x.qca.nfc.card

import de.connect2x.lognity.api.logger.Logger
import de.connect2x.qca.nfc.card.apdu.ResponseException
import de.connect2x.qca.nfc.card.apdu.ResponseStatus
import de.connect2x.qca.nfc.card.command.EncryptedPinFormat2
import de.connect2x.qca.nfc.card.command.pinCommandResetRetryCounterWithPukWithoutNewSecret
import de.connect2x.qca.nfc.card.command.pinCommandVerify

private val log = Logger("de.connect2x.qca.nfc.card.SecuredNfcChannelPin")

internal suspend fun SecuredNfcChannel.verifyPin(pin: String, cardInfo: NfcCardInfo) {
    log.debug { "verify PIN" }
    require(cardInfo.pinVerificationPasswordId != null) { "Password id not available." }
    try {
        transmit(pinCommandVerify(EncryptedPinFormat2(pin), cardInfo.pinVerificationPasswordId))
    } catch (responseException: ResponseException) {
        when (val status = responseException.responseStatus) {
            ResponseStatus.SUCCESS -> {}
            ResponseStatus.WRONG_SECRET_WARNING_COUNT_03 ->
                throw NfcAuthenticationFailedException(NfcAuthenticationFailedReason.PinWrong(3))

            ResponseStatus.WRONG_SECRET_WARNING_COUNT_02 ->
                throw NfcAuthenticationFailedException(NfcAuthenticationFailedReason.PinWrong(2))

            ResponseStatus.WRONG_SECRET_WARNING_COUNT_01 ->
                throw NfcAuthenticationFailedException(NfcAuthenticationFailedReason.PinWrong(1))

            ResponseStatus.PASSWORD_BLOCKED ->
                throw NfcAuthenticationFailedException(NfcAuthenticationFailedReason.PinLocked)

            ResponseStatus.PASSWORD_NOT_USABLE ->
                throw NfcAuthenticationFailedException(NfcAuthenticationFailedReason.PinNotUsable)

            else -> {
                throw NfcAuthenticationFailedException(NfcAuthenticationFailedReason.Unknown(status.name))
            }
        }
    }
}

internal suspend fun SecuredNfcChannel.unlockCard(puk: String, cardInfo: NfcCardInfo) {
    log.debug { "unlock card" }
    require(cardInfo.pinVerificationPasswordId != null) { "Password id not available." }
    val responseApdu = transmit(
        pinCommandResetRetryCounterWithPukWithoutNewSecret(
            EncryptedPinFormat2(puk),
            cardInfo.pinVerificationPasswordId
        )
    )
    when (responseApdu.status) {
        ResponseStatus.SUCCESS -> {}
        ResponseStatus.WRONG_SECRET_WARNING_COUNT_09 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(9))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_08 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(8))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_07 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(7))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_06 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(6))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_05 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(5))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_04 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(4))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_03 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(3))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_02 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(2))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_01 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(1))

        ResponseStatus.WRONG_SECRET_WARNING_COUNT_00 ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukRetriesLeft(0))

        ResponseStatus.PUK_BLOCKED ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.PukBlocked)

        ResponseStatus.WRONG_PASSWORD_LENGTH ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.InvalidLength)

        ResponseStatus.SECURITY_STATUS_NOT_SATISFIED ->
            throw NfcUnlockFailedException(NfcUnlockFailedReason.SecurityStatusNotSatisfied)

        else -> {
            throw NfcUnlockFailedException(NfcUnlockFailedReason.UserNotAuthenticated)
        }
    }
}