package de.connect2x.qca.nfc.card.pace

import de.connect2x.qca.crypto.asn1.Asn1
import de.connect2x.qca.crypto.asn1.Asn1Tag
import de.connect2x.qca.crypto.asn1.derEncodeWithTagAndLengthBytes
import de.connect2x.qca.crypto.deriveAes128CbcCmac

private const val RAW_PACE_ECDH_GM_AES_CBCCMAC_128_PROTOCOL_ID = "0.4.0.127.0.7.2.2.4.2.2"

internal fun createAsn1AuthToken(publicKeyData: ByteArray): ByteArray {
    val publicKeyDataTag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0x06, Asn1Tag.DerEncodingForm.PRIMITIVE)
    val encodedPublicKeyData = Asn1.derEncodeWithTagAndLengthBytes(publicKeyDataTag, publicKeyData)

    val oid = Asn1.toObjectIdentifier(RAW_PACE_ECDH_GM_AES_CBCCMAC_128_PROTOCOL_ID)
    // replace tag
    val serializedOid =
        Asn1Tag(Asn1Tag.TagClass.UNIVERSAL, 0x06, Asn1Tag.DerEncodingForm.PRIMITIVE).rawBytes + oid.copyOfRange(
            1,
            oid.size
        )

    val constructedTag = Asn1Tag(Asn1Tag.TagClass.APPLICATION, 0x49, Asn1Tag.DerEncodingForm.CONSTRUCTED)
    return Asn1.derEncodeWithTagAndLengthBytes(constructedTag, serializedOid + encodedPublicKeyData)
}

fun ByteArray.paceMac(
    macKey: ByteArray
): ByteArray {
    val authToken = createAsn1AuthToken(this)
    return authToken.deriveAes128CbcCmac(macKey)
}
