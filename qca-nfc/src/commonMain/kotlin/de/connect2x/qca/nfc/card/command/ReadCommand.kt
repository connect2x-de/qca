package de.connect2x.qca.nfc.card.command

import de.connect2x.qca.nfc.card.Ef
import de.connect2x.qca.nfc.card.SecuredNfcChannel
import de.connect2x.qca.nfc.card.apdu.CommandApdu
import de.connect2x.qca.nfc.card.apdu.CommandApdu.Companion.CommandApdu
import de.connect2x.qca.nfc.card.apdu.EXPECT_ALL_WILDCARD
import de.connect2x.qca.nfc.card.apdu.readStatus
import de.connect2x.qca.nfc.card.apdu.readStructuredEfStatus

// gemSpec_COS#(N066.100)
/// Reads AID.MF from EF.DIR
internal fun SecuredNfcChannel.readCommandCardType(): CommandApdu {
    // p1: gemSpec_HBA_ObjSys#(Tab_HBA_ObjSys_007) index of record in recordList to be read, i.e. 1st record = AID.MF
    // p2: (shortFileIdentifier << 3) + '04' ; gemSpec_HBA_ObjSys#(Tab_HBA_ObjSys_007) shortFileIdentifier = 1E
    // Use cases Read Record with and without shortFileIdentifier gemSpec_COS#14.4.6.1 - 14.4.6.2
    return CommandApdu(
        expectedStatus = readStructuredEfStatus,
        cla = 0x00,
        ins = (0xB2u).toByte(),
        p1 = 0x01,
        p2 = (0xF4).toByte(),
        data = null,
        ne = EXPECT_ALL_WILDCARD,
    )
}

internal fun SecuredNfcChannel.readCommandEfVersion2(): CommandApdu {
    // gemSpec_COS#14.3.2.2 Use case Read Binary with `ShortFileIdentifier`
    // 0x80 is a marker for setting the first bit (i.e. **0x80**) when working with `ShortFileIdentifier`
    // 0x11 is the sfid of MF/EF.VERSION2
    // length is either 43 bytes for eGK or 38 bytes for HBA, so EXPECTED_LENGTH_WILDCARD_SHORT may also be sufficient
    // use EXPECT_ALL_WILDCARD anyway - it won't hurt
    return CommandApdu(
        expectedStatus = readStructuredEfStatus,
        cla = 0x00,
        ins = (0xB0).toByte(),
        p1 = (0x80 + Ef.Version2.SFID).toByte(),
        p2 = 0x00,
        data = null,
        ne = EXPECT_ALL_WILDCARD,
    )
}

/**
 * Read from selected file
 * gemSpec_COS#(N051.100) gemSpec_COS#14.3.2.1
 * @param offset where to start reading
 * @param length bytes to read
 */
internal fun SecuredNfcChannel.readCommandBinary(offset: Int, length: Int): CommandApdu {
    // gemSpec_COS#N050.900
    require(offset in 0..32767) { "Invalid offset when reading binary." }
    val p2 = offset % 256
    val p1 = (offset - p2) / 256
    return CommandApdu(
        expectedStatus = readStatus,
        cla = 0x00,
        ins = (0xB0).toByte(),
        p1 = p1.toByte(),
        p2 = p2.toByte(),
        data = null,
        ne = length,
    )
}