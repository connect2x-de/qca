package de.connect2x.qca.nfc.card.pace

import de.connect2x.qca.crypto.asn1.*
import de.connect2x.qca.crypto.decryptAes128Cbc
import de.connect2x.qca.crypto.deriveAes128CbcCmac
import de.connect2x.qca.crypto.encryptAes128Cbc
import de.connect2x.qca.crypto.encryptAes128Ecb
import de.connect2x.qca.nfc.card.apdu.*
import kotlin.experimental.or

private const val SECURE_MESSAGING_COMMAND: Byte = 0x0C
private val PADDING_INDICATOR = byteArrayOf(0x01)
private const val BLOCK_SIZE = 16

// sizes in bytes
private const val MIN_RESPONSE_SIZE = 14
private const val RESPONSE_TRAILER_SIZE = 2
private const val RESPONSE_MAC_SIZE = 10
private const val RESPONSE_STATUS_SIZE = 4

// ISO/IEC 7816-4 padding tag
private const val PAD: Byte = 0x80.toByte()

// gemSpec_COS#13.2
// enc: symmetric key for encoding (N029.900)d.2
// mac: symmetric key for mac processing (N029.900)d.4
// secureMessagingSSC: gemSpec_COS#13.2 random non-negative number which is used as 'send sequence counter' in mac processing (N029.900)d.5
internal class PaceKey(
    internal val encryptionKey: ByteArray,
    val macKey: ByteArray,
    private val secureMessagingSSC: ByteArray = ByteArray(BLOCK_SIZE)
) {

    private fun incrementSSC() {
        for (i in secureMessagingSSC.indices.reversed()) {
            secureMessagingSSC[i]++
            if (secureMessagingSSC[i] != 0x00.toByte()) break
        }
    }

    /**
     * Encrypts a plain APDU
     *
     * @param commandApdu plain Command APDU
     * @return encrypted Command APDU
     */
    fun encrypt(
        commandApdu: CommandApdu, isExtendedLengthSupported: Boolean,
        maxTransceiveLength: Int
    ): CommandApdu {
        incrementSSC()
        val header = commandApdu.header
        // [REQ:gemSpec_COS:N032.500] Indicate Secure Messaging (Caution: we assume CLA in [0,3]!)
        require(header[0] != (header[0] or SECURE_MESSAGING_COMMAND)) { "Malformed Secure Messaging APDU. Invalid header." }
        header[0] = (header[0] or SECURE_MESSAGING_COMMAND)

        val encryptedData = encryptData(commandApdu.data)

        // get length object
        val lengthData = createLengthData(commandApdu.ne)

        val tmpData = encryptedData + lengthData
        // [REQ:gemSpec_COS:N032.900] Build APDU
        val cmac = calculateCmac(macIn = header, data = tmpData)
        val macTag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0xE, Asn1Tag.DerEncodingForm.PRIMITIVE)
        val cmacEncoded = Asn1.derEncodeWithTagAndLengthBytes(macTag, cmac)

        val newD = tmpData + cmacEncoded
        val ne = createNe(le = commandApdu.ne, dataSize = commandApdu.data?.size ?: 0, newDSize = newD.size)
        return CommandApdu(
            cla = header[0],
            ins = header[1],
            p1 = header[2],
            p2 = header[3],
            data = newD,
            initialNe = ne,
            expectedStatus = commandApdu.expectedStatus,
            isExtendedLengthSupported = isExtendedLengthSupported,
            maxTransceiveLength = maxTransceiveLength
        )
    }

    private fun encryptData(data: ByteArray?) =
        if (data == null || data.isEmpty()) byteArrayOf()
        else {
            val paddedData = padData(data, BLOCK_SIZE)
            // ECB instead of CBC on purpose. COS doesn't support CBC for this.
            val initVector = secureMessagingSSC.encryptAes128Ecb(encryptionKey)
            // add padding indicator
            val encryptedData = PADDING_INDICATOR + paddedData.encryptAes128Cbc(encryptionKey, initVector)

            // write encrypted data to output
            val tag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0x07, Asn1Tag.DerEncodingForm.PRIMITIVE)
            Asn1.derEncodeWithTagAndLengthBytes(tag, encryptedData)
        }

    private fun createLengthData(le: Int): ByteArray {
        val leData = when {
            le == EXPECTED_LENGTH_WILDCARD_SHORT -> byteArrayOf(0x00)
            le == EXPECTED_LENGTH_WILDCARD_EXTENDED -> byteArrayOf(0x00, 0x00)
            le > EXPECTED_LENGTH_WILDCARD_SHORT -> byteArrayOf((le shr 8 and 0xFF).toByte(), (le and 0xFF).toByte())
            le >= 0 -> byteArrayOf((le and 0xFF).toByte())
            else -> return byteArrayOf()
        }
        val tag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0x17, Asn1Tag.DerEncodingForm.PRIMITIVE)
        return Asn1.derEncodeWithTagAndLengthBytes(tag, leData)
    }

    // [REQ:gemSpec_COS:N033.100,N033.200,N033.300,N033.400]
    private fun createNe(
        le: Int,
        dataSize: Int,
        newDSize: Int,
    ) = when {
        dataSize < 1 && le == NO_EXPECTED_RESPONSE_DATA -> EXPECTED_LENGTH_WILDCARD_SHORT
        dataSize < 1 && le > -1 -> EXPECTED_LENGTH_WILDCARD_EXTENDED
        dataSize > 0 && le < 0 && newDSize <= 255 -> EXPECTED_LENGTH_WILDCARD_SHORT
        else -> EXPECTED_LENGTH_WILDCARD_EXTENDED
    }

    /**
     * Decrypts an encrypted Response APDU
     * Read APDU structure - gemSpec_COS#13.3
     * Case 1: DO99|DO8E|SW1SW2
     * Case 2: DO87|DO99|DO8E|SW1SW2
     * Case 3: DO99|DO8E|SW1SW2
     * Case 4: DO87|DO99|DO8E|SW1SW2
     */
    fun decrypt(responseApdu: ResponseApdu): ByteArray {
        incrementSSC()
        val data = responseApdu.data

        val macBytes = data.copyOfRange(data.size - RESPONSE_MAC_SIZE, data.size)
        val statusBytes =
            data.copyOfRange(data.size - RESPONSE_STATUS_SIZE - RESPONSE_MAC_SIZE, data.size - RESPONSE_MAC_SIZE)
        val messageBytes = data.copyOfRange(0, data.size - RESPONSE_STATUS_SIZE - RESPONSE_MAC_SIZE)
        // mac
        val do8eTag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0xE, Asn1Tag.DerEncodingForm.PRIMITIVE)
        val responseMac = Asn1.derDecode(do8eTag, macBytes).content as Asn1Node.Content.Primitive
        // all bytes before mac is protected
        val protectedData = messageBytes + statusBytes
        val calculatedMac = calculateCmac(protectedData)
        require(responseMac.data contentEquals calculatedMac) { "Secure Messaging MAC verification failed" }

        // status
        val do99Tag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0x19, Asn1Tag.DerEncodingForm.PRIMITIVE)
        val statusData = Asn1.derDecode(do99Tag, statusBytes).content as Asn1Node.Content.Primitive

        // message
        val decryptedData = decryptMessage(messageBytes)
        return (decryptedData + statusData.data)
    }

    private fun decryptMessage(messageBytes: ByteArray) = if (messageBytes.isEmpty()) {
        byteArrayOf()
    } else {
        // check if encrypted (0x7) or not (0x1)
        val encryptedTag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0x7, Asn1Tag.DerEncodingForm.PRIMITIVE)
        val notEncryptedTag = Asn1Tag(Asn1Tag.TagClass.CONTEXT_DEFINED, 0x1, Asn1Tag.DerEncodingForm.PRIMITIVE)
        val messageNode = Asn1.derDecode(messageBytes)
        val message = (messageNode.content as Asn1Node.Content.Primitive).data
        when (messageNode.tag) {
            encryptedTag -> {
                // Encrypted data - N033.800
                // ECB instead of CBC on purpose. COS doesn't support CBC for this.
                val initVector = secureMessagingSSC.encryptAes128Ecb(encryptionKey)
                val paddedDecryptedData =
                    removePaddingIndicator(message).decryptAes128Cbc(encryptionKey, initVector)
                unPadData(paddedDecryptedData)
            }

            notEncryptedTag -> message
            else -> throw IllegalStateException("Unexpected tag when decrypting message.")

        }
    }

    private fun removePaddingIndicator(dataBytes: ByteArray): ByteArray =
        dataBytes.copyOfRange(1, dataBytes.size)


    private fun calculateCmac(macIn: ByteArray, data: ByteArray? = null): ByteArray {
        val paddedMacIn = padData(macIn, BLOCK_SIZE)
        val macData = if (data == null || data.isEmpty()) {
            secureMessagingSSC + paddedMacIn
        } else {
            val paddedData = padData(data, BLOCK_SIZE)
            secureMessagingSSC + paddedMacIn + paddedData
        }
        return macData.deriveAes128CbcCmac(macKey)
    }

    /**
     * Padding the data with [PAD].
     *
     * @param data byte array with data
     * @param blockSize int
     * @return byte array with padded data
     */
    private fun padData(data: ByteArray, blockSize: Int): ByteArray =
        ByteArray(data.size + (blockSize - data.size % blockSize)).apply {
            data.copyInto(this)
            this[data.size] = PAD
        }

    /**
     * Unpadding the data.
     *
     * @param paddedData byte array with padded data
     * @return byte array with data
     */
    private fun unPadData(paddedData: ByteArray): ByteArray {
        for (i in paddedData.indices.reversed()) {
            if (paddedData[i] == PAD) {
                return paddedData.copyOfRange(0, i)
            }
        }
        return paddedData
    }
}