package de.connect2x.qca.nfc.card

import de.connect2x.qca.crypto.asn1.Asn1
import de.connect2x.qca.crypto.asn1.Asn1Node
import de.connect2x.qca.crypto.asn1.Asn1Tag
import de.connect2x.qca.crypto.asn1.derDecode
import de.connect2x.qca.nfc.card.command.readCommandCardType
import de.connect2x.qca.nfc.card.command.readCommandEfVersion2
import io.github.oshai.kotlinlogging.KotlinLogging

private val log = KotlinLogging.logger { }

data class NfcCardInfo(
    val type: CardType,
    val generation: CardGeneration
) {
    @OptIn(ExperimentalStdlibApi::class)
    val signingCertificateFileIdentifier: ByteArray? = when (type) {
        CardType.HBA -> if (generation == CardGeneration.G2_1) {
            // gemSpec_HBA_ObjSys_G2_1_V5.2.0#5.6.2.7 for EF.C.HP.AUT.E256 file identifier
            Mf.Df.Esign.Ef.CHpAutE256.FID.toShort().toHexString().hexToByteArray()
        } else {
            Mf.Df.Esign.Ef.CHpAutR2048.FID.toShort().toHexString().hexToByteArray()
        }

        CardType.EGK -> Mf.Df.Esign.Ef.CChAutE256.FID.toShort().toHexString().hexToByteArray()
        else -> null
    }

    val privateKeyIdentifier: Byte? = when (type) {
        CardType.HBA -> if (generation == CardGeneration.G2_1) {
            // gemSpec_HBA_ObjSys_G2_1_V5.2.0#5.6.2.5
            Mf.Df.Esign.PrK.HpAutE256.KID.toByte()
        } else {
            // gemSpec_HBA_ObjSys_G2_1_V5.2.0#5.6.2.1
            Mf.Df.Esign.PrK.HpAutR2048.KID.toByte()
        }
        // gemSpec_eGK_ObjSys_G2_1_V4.5.0#5.5.13
        CardType.EGK -> Mf.Df.Esign.PrK.ChAutE256.KID.toByte()
        else -> null
    }

    // gemSpec_COS#16.1
    val algorithmIdentifier: Byte? = when (type) {
        CardType.HBA -> if (generation == CardGeneration.G2_1) {
            PSOAlgorithm.signECDSA.identifier
        } else {
            PSOAlgorithm.signPSS.identifier
        }

        CardType.EGK -> PSOAlgorithm.signECDSA.identifier
        else -> null
    }

    // gemSpec_IDP_Frontend#9.3.6
    val pinVerificationPasswordId: Byte? = when (type) {
        CardType.HBA -> 1 // PIN CH
        CardType.EGK -> 2 // MR.PIN.HOME
        else -> null
    }
}

// `ApplicationIdentifier` of the application the card is initialised with
enum class CardType(val hexString: String? = null) {
    EGK(hexString = "61094f07d2760001448000"),
    HBA(hexString = "61084f06d27600014601"),
    UNKNOWN();

    companion object {
        fun from(hexString: String?): CardType {
            return when (hexString) {
                EGK.hexString -> EGK
                HBA.hexString -> HBA
                else -> UNKNOWN
            }
        }
    }
}

/// Represent the card generation of health card
///
/// | Version   | Version with 2 digits | INT Value for Version | Card generation
/// | < 3.0.3   |  03.00.03             | 30003                 | G1
/// | < 4.0.0   |  04.00.00             | 40000                 | G1P
/// | >= 4.0.0  |  04.00.00             | 40000                 | G2
/// | >= 4.4.0  |  04.04.00             | 40400                 | G2_1
///
enum class CardGeneration {
    // Generation G1 (< 3.0.3)
    G1,

    // Generation G1P (3.0.3 - < 4.0.0)
    G1P,

    // Generation G2 (4.0.0 - < 4.4.0)
    G2,

    // Generation G2.1 (4.4.0+)
    G2_1,
    UNKNOWN;


    companion object {
        private val version_3_0_3 = 30003
        private val version_4_0_0 = 40000
        private val version_4_4_0 = 40400

        /**
         * @param version value like 30003, 40000 (for details see class description)
         * @return CardGeneration for ObjectSystemVersion
         */
        fun from(version: Int): CardGeneration =
            when (version) {
                in 0..<version_3_0_3 -> G1
                in version_3_0_3..<version_4_0_0 -> G1P
                in version_4_0_0..<version_4_4_0 -> G2
                in version_4_4_0..Int.MAX_VALUE -> G2_1
                else -> UNKNOWN
            }


        /**
         * Parse the CardGeneration from the `objectSystemVersion` from the `CardVersion2`
         */
        @OptIn(ExperimentalStdlibApi::class)
        fun from(data: ByteArray): CardGeneration {
            // Length in bytes [objectSystemVersion] is 3
            // gemSpec_COS#5.3
            // gemSpec_Karten_Fach_TIP_G2_1_V3.0.0#2.1.2
            if (data.size != 3) {
                return UNKNOWN
            }
            // according to spec convert to hex string
            // https://kotlinlang.org/api/latest/jvm/stdlib/kotlin.text/-hex-format/-number-hex-format/
            // toHexString uses HexFormat.Default that is no leading zeros are removed
            // and by default all 4 bits are represented by a single hex digit, i.e. 8 bits lead to 2-digit-hex string
            val versionString = data.toHexString()
            // Radix 10 is not entirely correct here, but we assume version nrs not to grow beyond 99
            // See also Java implementation: de.gematik.ti.healthcard.control.entities.CardGeneration
            val versionInt = versionString.toInt(10)


            return from(versionInt)
        }
    }
}

// gemSpec_COS#16.1
enum class PSOAlgorithm(val identifier: Byte) {
    signPSS(5),
    signECDSA(0)
}

@OptIn(ExperimentalStdlibApi::class)
internal suspend fun SecuredNfcChannel.retrieveCardInfo(): NfcCardInfo {
    log.debug { "Determine card type" }
    val responseApdu = transmit(readCommandCardType())
    val cardType = CardType.from(responseApdu.data.toHexString())

    log.debug { "Determine card version" }
    // gemSpec_Karten_Fach_TIP_G2_1_3_0_0 #2.3 EF.Version2
    val efVersion2Response = transmit(readCommandEfVersion2())
    val decoded = Asn1.derDecode(efVersion2Response.data).content as Asn1Node.Content.Constructed
    val versionNode =
        decoded.nodes.first { it.tag == Asn1Tag(Asn1Tag.TagClass.PRIVATE, 1, Asn1Tag.DerEncodingForm.PRIMITIVE) }
    val version = (versionNode.content as Asn1Node.Content.Primitive).data
    val generation = CardGeneration.from(version)
    val cardInfo = NfcCardInfo(cardType, generation)
    log.debug { "retrieved cardInfo: $cardInfo" }
    return cardInfo
}