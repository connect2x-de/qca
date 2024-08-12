package de.connect2x.qca.nfc.card.pace

import de.connect2x.qca.crypto.asn1.Asn1
import de.connect2x.qca.crypto.asn1.Asn1Node
import de.connect2x.qca.crypto.asn1.Asn1Tag
import de.connect2x.qca.crypto.asn1.derDecode

internal object PaceResponse {
    // ISO/EIC 7816-4 - C.2 - Internal Authenticate
    // command  : {'7C'-'02'-{'80'-'00'}}
    // response : {'7C'-L1 (=2+L2)-{'80'-L2-Witness}}
    // BSI_TR-03110_Part-3-V2_2: B.1. for all protocol specific data objects
    fun parseStep1Response(data: ByteArray): ByteArray =
        parseGeneralAuthenticateResponse(Asn1Tag(byteArrayOf(0x80.toByte())), data)

    fun parseStep2Response(data: ByteArray): ByteArray =
        parseGeneralAuthenticateResponse(Asn1Tag(byteArrayOf(0x82.toByte())), data)

    fun parseStep3Response(data: ByteArray): ByteArray =
        parseGeneralAuthenticateResponse(Asn1Tag(byteArrayOf(0x84.toByte())), data)

    fun parseStep4Response(data: ByteArray): ByteArray =
        parseGeneralAuthenticateResponse(Asn1Tag(byteArrayOf(0x86.toByte())), data)

    // BSI_TR-03110_Part-3-V2_2: B.1. for all protocol specific data objects
    private fun parseGeneralAuthenticateResponse(innerTag: Asn1Tag, data: ByteArray): ByteArray {
        val outerTag = Asn1Tag(byteArrayOf(0x7C))
        val constructedData = Asn1.derDecode(outerTag, data).content as Asn1Node.Content.Constructed
        val primitiveNode = constructedData.nodes[0]
        require(innerTag == primitiveNode.tag) { "Unexpected inner tag" }
        return (primitiveNode.content as Asn1Node.Content.Primitive).data
    }
}