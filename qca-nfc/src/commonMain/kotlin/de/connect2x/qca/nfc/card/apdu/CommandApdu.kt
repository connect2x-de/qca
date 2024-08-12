package de.connect2x.qca.nfc.card.apdu

import de.connect2x.qca.nfc.card.NfcChannelBase


/**
 * Expected response lengths.
 */
internal const val EXPECTED_LENGTH_WILDCARD_EXTENDED: Int = 65536
internal const val EXPECTED_LENGTH_WILDCARD_SHORT: Int = 256
internal const val EXPECT_ALL_WILDCARD: Int = Int.MAX_VALUE
internal const val NO_EXPECTED_RESPONSE_DATA: Int = -1

/**
 * An APDU (Application Protocol Data Unit) Command per ISO/IEC 7816-4.
 * Command APDU encoding options:
 *
 * ```
 * case 1:  |CLA|INS|P1 |P2 |                                 len = 4
 * case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
 * case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
 * case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
 * case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
 * case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
 * case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len =10..65544
 *
 * LE, LE1, LE2 may be 0x00.
 * LC must not be 0x00 and LC1|LC2 must not be 0x00|0x00
 * ```
 * gemSpec_COS#11.5 - 11.7
 * note: gemSpec_COS#11.7.2.2 contradicts ISO/IEC 7816-4#5.1
 * This implementation adheres to ISO/IEC 7816-4 so ne = 256 is encoded as a single byte in case 2 scenarios
 */
class CommandApdu(
    val cla: Byte,
    val ins: Byte,
    val p1: Byte,
    val p2: Byte,
    val data: ByteArray?,
    initialNe: Int,
    val expectedStatus: Map<Int, ResponseStatus>,
    isExtendedLengthSupported: Boolean,
    maxTransceiveLength: Int,
) {
    companion object {
        fun NfcChannelBase.CommandApdu(
            cla: Byte,
            ins: Byte,
            p1: Byte,
            p2: Byte,
            data: ByteArray?,
            ne: Int,
            expectedStatus: Map<Int, ResponseStatus>,
        ) = CommandApdu(cla, ins, p1, p2, data, ne, expectedStatus, isExtendedLengthSupported, maxTransceiveLength)
    }

    // |CLA|INS|P1 |P2 |
    private val _header = byteArrayOf(cla, ins, p1, p2)
    val header get() = _header.copyOf()

    val ne: Int = kotlin.run {
        if (initialNe == EXPECT_ALL_WILDCARD) {
            if (isExtendedLengthSupported) EXPECTED_LENGTH_WILDCARD_EXTENDED
            else EXPECTED_LENGTH_WILDCARD_SHORT
        } else initialNe
    }

    private val _apduBytes: ByteArray = run {
        require(ne <= EXPECTED_LENGTH_WILDCARD_EXTENDED && ne >= -1) {
            "Command APDU length is out of bounds [-1, 65536], got $ne"
        }
        val bytes = if (data != null) {
            val nc = data.size
            require(nc <= 65535) { "ADPU cmd data length must not exceed 65535 bytes" }

            val lengthPlusData =
                if (ne != -1) {
                    // case 4s or 4e
                    if (nc <= 255 && ne <= EXPECTED_LENGTH_WILDCARD_SHORT) {
                        // case 4s
                        encodeDataLengthShort(nc) + data + encodeExpectedLengthShort(ne)
                    } else {
                        // case 4e
                        encodeDataLengthExtended(nc) + data + encodeExpectedLengthExtended(ne)
                    }
                } else {
                    // case 3s or 3e
                    if (nc <= 255) {
                        // case 3s
                        encodeDataLengthShort(nc) + data
                    } else {
                        // case 3e
                        encodeDataLengthExtended(nc) + data
                    }
                }
            header + lengthPlusData
        } else {
            // data empty
            if (ne != -1) {
                // case 2s or 2e
                val lengthBytes = if (ne <= EXPECTED_LENGTH_WILDCARD_SHORT) {
                    // case 2s
                    // 256 is encoded 0x0
                    encodeExpectedLengthShort(ne)
                } else {
                    // case 2e
                    byteArrayOf(0x0) + encodeExpectedLengthExtended(ne)
                }
                header + lengthBytes
            } else {
                // case 1
                header
            }
        }
        val apduLength = bytes.size
        require(apduLength <= maxTransceiveLength) {
            "CommandApdu is too long to send. Limit for Reader is $maxTransceiveLength but length of commandApdu is $apduLength"
        }
        bytes
    }
    val apduBytes
        get() = _apduBytes.copyOf()

    private fun encodeDataLengthExtended(nc: Int) = byteArrayOf(0x0, (nc shr 8).toByte(), (nc and 0xFF).toByte())

    private fun encodeDataLengthShort(nc: Int) = byteArrayOf(nc.toByte())

    private fun encodeExpectedLengthExtended(ne: Int) =
        if (ne == EXPECTED_LENGTH_WILDCARD_EXTENDED) byteArrayOf(0x0, 0x0)
        else byteArrayOf((ne shr 8).toByte(), (ne and 0xFF).toByte()) // l1, l2


    private fun encodeExpectedLengthShort(ne: Int) = byteArrayOf(
        if (ne == EXPECTED_LENGTH_WILDCARD_SHORT) 0x0
        else ne.toByte()
    )
}