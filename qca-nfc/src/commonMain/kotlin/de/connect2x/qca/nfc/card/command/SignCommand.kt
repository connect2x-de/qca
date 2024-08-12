package de.connect2x.qca.nfc.card.command

import de.connect2x.qca.nfc.card.SecuredNfcChannel
import de.connect2x.qca.nfc.card.apdu.CommandApdu.Companion.CommandApdu
import de.connect2x.qca.nfc.card.apdu.EXPECT_ALL_WILDCARD
import de.connect2x.qca.nfc.card.apdu.psoComputeDigitalSignatureStatus

/**
 * Command representing Compute Digital Signature in gemSpec_COS#14.8.2
 */
internal fun SecuredNfcChannel.signCommandPsoComputeDigitalSignature(dataToBeSigned: ByteArray) = CommandApdu(
    expectedStatus = psoComputeDigitalSignatureStatus,
    cla = 0x00,
    ins = 0x2A,
    p1 = (0x9E).toByte(),
    p2 = (0x9A).toByte(),
    data = dataToBeSigned,
    // EXPECTED_LENGTH_WILDCARD_SHORT may be sufficient: for signPSS it's 64 bytes (gemSpec_COS#14.8.2.1) and for signECDSA it's twice the input bytes, which is 32 (sha256 hash) * 2 = 64
    ne = EXPECT_ALL_WILDCARD
)