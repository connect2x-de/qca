package de.connect2x.qca.nfc.card.command

import de.connect2x.qca.nfc.card.SecuredNfcChannel
import de.connect2x.qca.nfc.card.apdu.CommandApdu.Companion.CommandApdu
import de.connect2x.qca.nfc.card.apdu.NO_EXPECTED_RESPONSE_DATA
import de.connect2x.qca.nfc.card.apdu.changeReferenceDataStatus
import de.connect2x.qca.nfc.card.apdu.resetRetryCounterStatus
import de.connect2x.qca.nfc.card.apdu.verifySecretStatus

/**
 * Command representing Verify Secret Command gemSpec_COS#14.6.6
 */
internal fun SecuredNfcChannel.pinCommandVerify(
    pin: EncryptedPinFormat2,
    passwordId: Byte,
) = CommandApdu(
    expectedStatus = verifySecretStatus,
    cla = 0x00,
    ins = 0x20,
    p1 = 0x00,
    p2 = passwordId,
    data = pin.bytes,
    ne = NO_EXPECTED_RESPONSE_DATA,
)

/**
 * Command representing Verify Secret Command gemSpec_COS#14.6.6
 */
internal fun SecuredNfcChannel.pinCommandStatus(passwordId: Byte) = CommandApdu(
    expectedStatus = verifySecretStatus,
    cla = (0x80u).toByte(),
    ins = 0x20,
    p1 = 0x00,
    p2 = passwordId,
    data = null,
    ne = NO_EXPECTED_RESPONSE_DATA,
)

/**
 * Use case change reference data  gemSpec_COS#14.6.1.1
 */
internal fun SecuredNfcChannel.pinCommandChangeReferenceData(
    passwordId: Byte,
    oldSecret: EncryptedPinFormat2,
    newSecret: EncryptedPinFormat2
) = CommandApdu(
    expectedStatus = changeReferenceDataStatus,
    cla = 0x00,
    ins = 0x24,
    p1 = 0x00,
    p2 = passwordId,
    data = oldSecret.bytes + newSecret.bytes,
    ne = NO_EXPECTED_RESPONSE_DATA,
)


/**
 * Use case unlock eGK without Secret (Pin) gemSpec_COS#14.6.5.1
 */
internal fun SecuredNfcChannel.pinCommandResetRetryCounterWithPukWithNewSecret(
    puk: EncryptedPinFormat2,
    newSecret: EncryptedPinFormat2,
    passwordId: Byte,
) = CommandApdu(
    expectedStatus = resetRetryCounterStatus,
    cla = 0x00,
    ins = 0x2C,
    p1 = 0x00,
    p2 = passwordId,
    data = puk.bytes + newSecret.bytes,
    ne = NO_EXPECTED_RESPONSE_DATA,
)

/**
 * Use case unlock eGK without Secret (Pin) gemSpec_COS#14.6.5.2
 */
internal fun SecuredNfcChannel.pinCommandResetRetryCounterWithPukWithoutNewSecret(
    puk: EncryptedPinFormat2,
    passwordId: Byte,
) = CommandApdu(
    expectedStatus = resetRetryCounterStatus,
    cla = 0x00,
    ins = 0x2C,
    p1 = 0x01,
    p2 = passwordId,
    data = puk.bytes,
    ne = NO_EXPECTED_RESPONSE_DATA,
)