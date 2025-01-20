package de.connect2x.qca.nfc.card

import de.connect2x.qca.crypto.asn1.Asn1
import de.connect2x.qca.crypto.asn1.Asn1Node
import de.connect2x.qca.crypto.asn1.derDecode
import de.connect2x.qca.crypto.sha256
import de.connect2x.qca.nfc.card.command.*
import io.github.oshai.kotlinlogging.KotlinLogging

private val log = KotlinLogging.logger { }

internal suspend fun SecuredNfcChannel.retrieveSigningCertificate(cardInfo: NfcCardInfo): ByteArray {
    log.debug { "open DF.ESIGN" }
    transmit(selectCommandDfEsign())

    require(cardInfo.signingCertificateFileIdentifier != null) { "Unknown certificate file identifier" }

    log.debug { "select certificate DF.ESIGN" }
    // file control parameter
    val fcpBytes = transmit(selectCommandFile(cardInfo.signingCertificateFileIdentifier)).data
    val fcpAsn1 = Asn1.derDecode(fcpBytes).content
    check(fcpAsn1 is Asn1Node.Content.Constructed)
    val fcpAsn1EndOfFilePosition = fcpAsn1.nodes.find { it.tag.tagNumber == 0x05 }?.content
    check(fcpAsn1EndOfFilePosition is Asn1Node.Content.Primitive)
    val endOfFilePosition = fcpAsn1EndOfFilePosition.data.toInt()

    var buffer = ByteArray(0)
    var offset = 0
    do {
        log.debug { "read certificate DF.ESIGN (offset=$offset, endOfFilePosition=$endOfFilePosition)" }
        val nextLength = minOf(maxTransceiveLength, endOfFilePosition - offset)
        val response = transmit(readCommandBinary(offset, nextLength))
        buffer += response.data
        offset += response.data.size
    } while (offset < endOfFilePosition)
    log.debug { "finished read certificate DF.ESIGN" }
    return buffer
}

internal fun ByteArray.toInt(): Int {
    require(size <= Int.SIZE_BYTES)
    return fold(0) { number, nextByte ->
        (number shl 8) or nextByte.toInt()
    }
}


internal suspend fun SecuredNfcChannel.signChallenge(challenge: ByteArray, cardInfo: NfcCardInfo): ByteArray {
    log.debug { "Sign challenge" }
    transmit(selectCommandDfEsign())
    require(cardInfo.privateKeyIdentifier != null) { "Invalid key identifier." }
    require(cardInfo.algorithmIdentifier != null) { "Invalid algorithm identifier." }
    transmit(selectCommandSigningKey(cardInfo.privateKeyIdentifier, cardInfo.algorithmIdentifier))
    // signPSS as well as signECDSA require this hash as pre-condition
    // gemSpec_IDP_Frontend#9.3.7.1 & 9.3.7.2
    // rfc8017#9.1.1
    // TR–03111#4.2.1.1
    val hash = challenge.sha256()
    return transmit(signCommandPsoComputeDigitalSignature(hash)).data
}