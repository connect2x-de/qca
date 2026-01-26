package de.connect2x.qca.nfc.card

import de.connect2x.lognity.api.logger.Logger
import de.connect2x.qca.crypto.sha256
import de.connect2x.qca.encoding.FileControlParameter
import de.connect2x.qca.nfc.card.command.readCommandBinary
import de.connect2x.qca.nfc.card.command.selectCommandDfEsign
import de.connect2x.qca.nfc.card.command.selectCommandFile
import de.connect2x.qca.nfc.card.command.selectCommandSigningKey
import de.connect2x.qca.nfc.card.command.signCommandPsoComputeDigitalSignature

private val log = Logger("de.connect2x.qca.nfc.card.SecuredNfcChannelSigning")

internal suspend fun SecuredNfcChannel.retrieveSigningCertificate(cardInfo: NfcCardInfo): ByteArray {
    log.debug { "open DF.ESIGN" }
    transmit(selectCommandDfEsign())

    require(cardInfo.signingCertificateFileIdentifier != null) { "Unknown certificate file identifier" }

    log.debug { "select certificate DF.ESIGN" }
    // file control parameter
    val fcpData = transmit(selectCommandFile(cardInfo.signingCertificateFileIdentifier)).data
    val fcp = FileControlParameter.decodeFromDer(fcpData)
    val endOfFilePosition = fcp.readSize?.intValue()
    requireNotNull(endOfFilePosition)

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