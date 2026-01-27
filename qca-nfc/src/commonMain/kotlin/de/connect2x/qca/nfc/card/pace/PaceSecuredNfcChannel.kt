package de.connect2x.qca.nfc.card.pace

import de.connect2x.lognity.api.logger.Logger
import de.connect2x.lognity.api.logger.error
import de.connect2x.qca.crypto.BrainpoolP256r1Key
import de.connect2x.qca.crypto.decryptAes128Cbc
import de.connect2x.qca.nfc.card.*
import de.connect2x.qca.nfc.card.apdu.CommandApdu
import de.connect2x.qca.nfc.card.apdu.ResponseApdu
import de.connect2x.qca.nfc.card.apdu.ResponseException
import de.connect2x.qca.nfc.card.apdu.ResponseStatus
import de.connect2x.qca.nfc.card.pace.EstablishPaceSecuredNfcChannel.allSteps

private val log = Logger("de.connect2x.qca.nfc.card.pace")

internal class PaceSecuredNfcChannel(
    private val nfcChannel: NfcChannel,
    private val paceKey: PaceKey
) : SecuredNfcChannel, NfcChannelBase by nfcChannel {
    override suspend fun transmit(commandApdu: CommandApdu): ResponseApdu {
        val encryptedCommandApdu =
            paceKey.encrypt(commandApdu, nfcChannel.isExtendedLengthSupported, nfcChannel.maxTransceiveLength)
        val encryptedResponseApdu = nfcChannel.transmit(encryptedCommandApdu)
        val responseBytes = paceKey.decrypt(encryptedResponseApdu)
        return ResponseApdu(responseBytes, commandApdu.expectedStatus).requireSuccess()
    }
}

/**
 * Opens a secure PACE Channel for secure messaging
 * Negotiate the PaceKey and return the object
 * picc = card
 * pcd = smartphone
 */
internal suspend fun NfcChannel.establishPaceSecuredNfcChannel(can: String): SecuredNfcChannel = try {
    log.debug { "establishPaceSecuredNfcChannel" }
    allSteps(can).also {
        log.debug { "finished establishPaceSecuredNfcChannel" }
    }

} catch (responseException: ResponseException) {
    log.error(responseException) { "error establishing SecuredNfcChannel" }
    if (responseException.responseStatus == ResponseStatus.AUTHENTICATION_FAILURE) {
        throw NfcAuthenticationFailedException(NfcAuthenticationFailedReason.CanWrong)
    }
    throw IllegalStateException("Invalid response status: ${responseException.responseStatus.name}")
}

internal object EstablishPaceSecuredNfcChannel {
    // PACE approach "id-PACE-ECDH-GM-AES-CBCCMAC-128" with key SK.CAN and key refernece keyRef='02'.
// todo - future-proof - check which algorithms are supported - decide on that (for now, 128 is enough)
// PACE w/o elyptic
// id-PACE-ECDH-GM-AES-CBC-CMAC-128 with brainpoolP256r1

    internal suspend fun NfcChannel.allSteps(can: String): SecuredNfcChannel {
        step0()
        val step1Result = step1(can)
        val (step2Result1, step2Result2) = step2(step1Result)
        val (step3Result1, step3Result2, step3Result3) = step3(step2Result1, step2Result2)
        val step4Result = step4(step3Result1, step3Result2, step3Result3)
        return PaceSecuredNfcChannel(this, step4Result)
    }

    /**
     * GENERAL AUTHENTICATE - PACE - Step 0a - Select PACE via MSE - N102.448
     * gemSpec_COS#14.9.9.7
     * gemSpec_IDP_Frontend#9.3.2.2
     * Prepare card for establishing a PACE channel
     */
    internal suspend fun NfcChannel.step0() {
        log.debug { "establishPaceSecuredNfcChannel: step0" }
        transmit(paceCommandStep0())
    }

    /**
     * GENERAL AUTHENTICATE - PACE - Step 1a
     * gemSpec_COS#(N106.550)a - Step 1a
     * gemSpec_COS#(N085.001) - ADPU
     * gemSpec_COS#14.7.2 - General Authenticate
     * Request cryptogram `z` from card and decrypt it into `s` by using `CAN`
     */
    internal suspend fun NfcChannel.step1(can: String): ByteArray {
        log.debug { "establishPaceSecuredNfcChannel: step1" }
        val nonceZBytes = transmit(paceCommandStep1()).data
        val nonceZBytesEncoded = PaceResponse.parseStep1Response(nonceZBytes)
        val canBytes = can.encodeToByteArray()
        val aes128Key = KeyDerivationFunction.getAES128Key(canBytes, KeyDerivationFunction.Mode.PASSWORD)
        val nonceS = nonceZBytesEncoded.decryptAes128Cbc(key = aes128Key)
        return nonceS
    }

    /**
     * GENERAL AUTHENTICATE - PACE - Step 2a
     * gemSpec_COS#(N106.552)a
     * Send `~PK1.PCD` to card and receive `~PK1.PICC` from card
     * Generate a second key pair.
     */
    internal suspend fun NfcChannel.step2(
        nonceS: ByteArray,
        keyPairOne: BrainpoolP256r1Key = BrainpoolP256r1Key(), // testing only!
        keyPairTwo: BrainpoolP256r1Key = BrainpoolP256r1Key(), // testing only!
    ): Pair<ByteArray, BrainpoolP256r1Key> {
        log.debug { "establishPaceSecuredNfcChannel: step2" }
        val responseData = transmit(paceCommandStep2(keyPairOne.publicKey)).data
        val peerKeyData = PaceResponse.parseStep2Response(responseData)
        val ephemeralSharedPublicKey = keyPairOne.paceMapNonce(peerKeyData, nonceS, keyPairTwo)
        return ephemeralSharedPublicKey to keyPairTwo
    }

    /**
     * GENERAL AUTHENTICATE - PACE - Step 3a
     * gemSpec_COS#(N106.556)
     * Send `~PK2.PCD` to card. Receive `~PK2.PICC` from card.
     * Generate PACE session key.
     */
    internal suspend fun NfcChannel.step3(
        ephemeralSharedPublicKey: ByteArray,
        keyPairTwo: BrainpoolP256r1Key,
    ): Triple<ByteArray, ByteArray, PaceKey> {
        log.debug { "establishPaceSecuredNfcChannel: step3" }
        val piccPk2Bytes = transmit(paceCommandStep3(ephemeralSharedPublicKey)).data
        val piccPublicKey = PaceResponse.parseStep3Response(piccPk2Bytes)
        val sharedSecretKBytes = keyPairTwo.sharedSecret(piccPublicKey)
        val paceKey = PaceKey(
            KeyDerivationFunction.getAES128Key(sharedSecretKBytes, KeyDerivationFunction.Mode.ENC),
            KeyDerivationFunction.getAES128Key(sharedSecretKBytes, KeyDerivationFunction.Mode.MAC)
        )
        return Triple(ephemeralSharedPublicKey, piccPublicKey, paceKey)
    }

    /**
     * GENERAL AUTHENTICATE - PACE - Step 4a
     * gemSpec_COS#(N106.560)
     * gemSpec_COS#(N085.066)e
     *  Send `T.PCD` to card. Receive `T.PICC` from card.
     * Validate.
     */
    internal suspend fun NfcChannel.step4(
        ephemeralSharedPublicKey: ByteArray,
        piccPublicKey: ByteArray,
        paceKey: PaceKey
    ): PaceKey {
        log.debug { "establishPaceSecuredNfcChannel: step4" }
        val pcdMac = piccPublicKey.paceMac(paceKey.macKey)
        val piccMacDerived = ephemeralSharedPublicKey.paceMac(paceKey.macKey)

        val piccMacBytes = transmit(paceCommandStep4(pcdMac)).data
        val piccMac = PaceResponse.parseStep4Response(piccMacBytes)

        require(piccMac contentEquals piccMacDerived) { "Invalid pace key" }
        log.debug { "PACE channel established" }
        return paceKey
    }
}