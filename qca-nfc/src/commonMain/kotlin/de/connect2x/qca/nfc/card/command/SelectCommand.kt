package de.connect2x.qca.nfc.card.command

import de.connect2x.qca.crypto.asn1.Asn1
import de.connect2x.qca.crypto.asn1.Asn1Tag
import de.connect2x.qca.crypto.asn1.derEncodeWithTagAndLengthBytes
import de.connect2x.qca.nfc.card.Df
import de.connect2x.qca.nfc.card.SecuredNfcChannel
import de.connect2x.qca.nfc.card.apdu.CommandApdu
import de.connect2x.qca.nfc.card.apdu.CommandApdu.Companion.CommandApdu
import de.connect2x.qca.nfc.card.apdu.EXPECT_ALL_WILDCARD
import de.connect2x.qca.nfc.card.apdu.NO_EXPECTED_RESPONSE_DATA
import de.connect2x.qca.nfc.card.apdu.selectStatus

/**
 * Use case Select master file gemSpec_Cos#14.2.6 (N040.800).
 */
internal fun SecuredNfcChannel.selectCommandMasterFile() = CommandApdu(
    expectedStatus = selectStatus,
    cla = 0x00,
    ins = (0xA4).toByte(),
    p1 = 0x04,
    p2 = 0x0C,
    data = null,
    ne = NO_EXPECTED_RESPONSE_DATA,
)

/**
 * Use case Select file with Application Identifier, first occurrence, no File Control Parameter gemSpec_Cos#14.2.6.5
 * gemSpec_Cos N042.700
 * gemSpec_IDP_Frontend#9.3.4
 * A000000167455349474E is the application identifier
 */
@OptIn(ExperimentalStdlibApi::class)
internal fun SecuredNfcChannel.selectCommandDfEsign() = CommandApdu(
    expectedStatus = selectStatus,
    cla = 0x00,
    ins = (0xA4).toByte(),
    p1 = 0x04,
    p2 = 0x0C,
    data = Df.Esign.AID.hexToByteArray(),
    ne = NO_EXPECTED_RESPONSE_DATA
)

/**
 * Select signing key for signing - gemSpec_COS#14.9.9.9
 * @param key: The key Identifier (N102.700)
 * @param algorithm: select the algorithm to be used for signing operations (N102.800)
 */
internal fun SecuredNfcChannel.selectCommandSigningKey(keyIdentifier: Byte, algorithm: Byte): CommandApdu {
    // gemSpec_COS#N099.600
    // location = '80' key is DF specific (DF = Dedicated File, see ISO/IEC 7816-4)
    val keyReference = (0x80 + keyIdentifier).toByte()
    return CommandApdu(
        expectedStatus = selectStatus,
        cla = 0x00,
        ins = 0x22,
        p1 = 0x41,
        p2 = (0xB6).toByte(),
        // '84 – 01 – keyRef || 80 – 01 – algId'
        data = Asn1.derEncodeWithTagAndLengthBytes(
            Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 4, Asn1Tag.DerEncodingForm.PRIMITIVE),
            byteArrayOf(keyReference)
        )
                + Asn1.derEncodeWithTagAndLengthBytes(
            Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0, Asn1Tag.DerEncodingForm.PRIMITIVE),
            byteArrayOf(algorithm)
        ),
        ne = NO_EXPECTED_RESPONSE_DATA
    )
}

/**
 * Use case Select EF with File Identifier gemSpec_Cos#14.2.6.14
 */
internal fun SecuredNfcChannel.selectCommandFile(fileIdentifier: ByteArray) = CommandApdu(
    expectedStatus = selectStatus,
    cla = 0x00,
    ins = (0xA4).toByte(),
    p1 = 0x02,
    p2 = 0x04,
    data = fileIdentifier,
    ne = EXPECT_ALL_WILDCARD
)

