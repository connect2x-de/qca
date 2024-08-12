package de.connect2x.qca.nfc.card.pace

import de.connect2x.qca.crypto.asn1.Asn1
import de.connect2x.qca.crypto.asn1.Asn1Tag
import de.connect2x.qca.crypto.asn1.derEncodeWithTagAndLengthBytes
import de.connect2x.qca.nfc.card.NfcChannel
import de.connect2x.qca.nfc.card.apdu.*
import de.connect2x.qca.nfc.card.apdu.CommandApdu.Companion.CommandApdu

internal fun NfcChannel.paceCommandStep0(): CommandApdu {
    val oidRaw = "0.4.0.127.0.7.2.2.4.2.2"
    val oid = Asn1.toObjectIdentifier(oidRaw)
    // update tag
    val serializedOid = Asn1Tag(
        Asn1Tag.TagClass.CONTEXT_DEFINED,
        0x00,
        Asn1Tag.DerEncodingForm.PRIMITIVE
    ).rawBytes + oid.copyOfRange(1, oid.size)
    val keyId: Byte = 0x02
    val keyLocation: Byte = 0x00
    val keyReference = byteArrayOf((keyId + keyLocation).toByte())
    val tag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0x03, Asn1Tag.DerEncodingForm.PRIMITIVE)
    val serializedKeyReference = Asn1.derEncodeWithTagAndLengthBytes(tag, keyReference)
    val data = serializedOid + serializedKeyReference

    return CommandApdu(
        cla = 0x00,
        ins = 0x22,
        p1 = 0xC1.toByte(),
        p2 = 0xA4.toByte(),
        data = data,
        ne = NO_EXPECTED_RESPONSE_DATA,
        expectedStatus = manageSecurityEnvironmentStatus,
    )
}

// gemSpec_COS#(N085.001)
// [0x7C, 0x0]
internal fun NfcChannel.paceCommandStep1() = generalAuthenticate(0x10, null, byteArrayOf())

// gemSpec_COS#(N085.003)
internal fun NfcChannel.paceCommandStep2(publicKeyData: ByteArray) =
    generalAuthenticate(0x10, 0x01, publicKeyData)

// gemSpec_COS#(N085.005)
internal fun NfcChannel.paceCommandStep3(publicKeyData: ByteArray) =
    generalAuthenticate(0x10, 0x03, publicKeyData)

// gemSpec_COS#(N085.007)
internal fun NfcChannel.paceCommandStep4(pcdMac: ByteArray) = generalAuthenticate(0x00, 0x05, pcdMac)

private fun NfcChannel.generalAuthenticate(
    instructionClass: Byte,
    tagNumber: Int?,
    data: ByteArray
): CommandApdu {
    val derData = if (data.isEmpty()) {
        data
    } else {
        require(tagNumber != null) { "No tag number provided." }
        // encode data
        val innerTag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, tagNumber, Asn1Tag.DerEncodingForm.PRIMITIVE)
        Asn1.derEncodeWithTagAndLengthBytes(innerTag, data)
    }
    val outerTag = Asn1Tag(Asn1Tag.TagClass.APPLICATION, 0x1C, Asn1Tag.DerEncodingForm.CONSTRUCTED)
    val derConstructedData = Asn1.derEncodeWithTagAndLengthBytes(outerTag, derData)
    return CommandApdu(
        cla = instructionClass,
        ins = 0x86.toByte(),
        p1 = 0x0,
        p2 = 0x0,
        data = derConstructedData,
        ne = EXPECTED_LENGTH_WILDCARD_SHORT,
        expectedStatus = generalAuthenticateStatus,
    )
}
