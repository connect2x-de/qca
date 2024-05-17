package de.connect2x.qca.crypto.asn1

// TODO UByteArray -> ByteArray
@OptIn(ExperimentalUnsignedTypes::class)
expect object Asn1 {

    fun toObjectIdentifier(oid: String): UByteArray

    fun toOctetString(data: UByteArray): UByteArray
}

@OptIn(ExperimentalUnsignedTypes::class)
fun Asn1.derEncodeWithTagAndLengthBytes(tag: Asn1Tag, data: UByteArray): UByteArray {
    // see https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes
    return tag.rawBytes + derLengthBytes(data.size) + data
}

@OptIn(ExperimentalUnsignedTypes::class)
fun Asn1.derLengthBytes(dataSize: Int): UByteArray {
    // see https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes
    // determine number of bytes
    val lengthBytes = if (dataSize <= 127) {
        // length can be encoded in length field
        ubyteArrayOf(dataSize.toUByte())
    } else {
//            val numberBitsForLength = data.size.toString(2).length
//            val numberBytesForLength = numberBitsForLength / 8 + if (numberBitsForLength % 8 > 0) 1 else 0
        var numberBytesForLength = 0
        var value = dataSize
        do {
            numberBytesForLength++
            value = value shr 8
        } while (value != 0)
        val buffer = UByteArray(numberBytesForLength)
        for (i in 0..<numberBytesForLength) buffer[numberBytesForLength - i - 1] = (dataSize shr (i * 8)).toUByte()
        // first bit of 'number bytes of length'-byte is set
        val lengthByte = (0x80 or numberBytesForLength).toUByte()
        ubyteArrayOf(lengthByte) + buffer
    }
    return lengthBytes
}

@OptIn(ExperimentalUnsignedTypes::class)
fun Asn1.derDecode(expectedTag: Asn1Tag, data: UByteArray): Asn1Node {
    val node = derDecode(data)
    require(node.tag == expectedTag) {
        "Tag ${
            node.tag.rawBytes.fold(
                "tagClass: ${node.tag.tagClass.flag} tagNumber: ${node.tag.tagNumber} encodingForm: ${node.tag.encodingForm.flag} bytes: "
            ) { s, b -> "$s$b, " }
        } does not equal expected tag ${
            expectedTag.rawBytes.fold(
                "tagClass: ${expectedTag.tagClass.flag} tagNumber: ${expectedTag.tagNumber} encodingForm: ${expectedTag.encodingForm.flag} bytes: "
            ) { s, b -> "$s$b, " }
        }"
    }
    return node
}

/**
 * @return pair of decoded tag and data
 */
@OptIn(ExperimentalUnsignedTypes::class)
fun Asn1.derDecode(encodedBytes: UByteArray): Asn1Node {
    val parsedData = extractLeadingData(encodedBytes)
    return nodeFromParsedData(parsedData)
}

@OptIn(ExperimentalUnsignedTypes::class)
private fun Asn1.nodeFromParsedData(parsedData: ParsedData): Asn1Node =
    if (parsedData.tag.encodingForm == Asn1Tag.DerEncodingForm.CONSTRUCTED) {
        // decode sequence of nodes
        var offset = 0
        val sequence = ArrayList<Asn1Node>()
        do {
            val dataSlice = parsedData.data.sliceArray(offset..<parsedData.data.size)
            val nextData = extractLeadingData(dataSlice)
            sequence.add(nodeFromParsedData(nextData))
            offset += nextData.tag.size + 1 + nextData.numberLengthBytes + nextData.dataLength
        } while (offset < parsedData.data.size)
        Asn1Node(parsedData.tag, Asn1Node.Content.Constructed(sequence.toTypedArray()))
    } else {
//        require(originalEncodedBytes.size == (parsedData.tag.size + 1 + parsedData.numberLengthBytes + parsedData.dataLength)) { "Invalid data size when creating primitive node" }
        Asn1Node(parsedData.tag, Asn1Node.Content.Primitive(parsedData.data))
    }

@OptIn(ExperimentalUnsignedTypes::class)
private fun Asn1.extractLeadingData(data: UByteArray): ParsedData {
    require(data.size >= 2) { "Invalid DER data" }
    val tagBytes = if (data[0].toInt() and 0x1F == 0x1F) {
        // extended tag
        // just cut data at the appropriate position
        val lastTagByteIndex = data.drop(1).indexOfFirst { it < 0x80u } + 1// find first byte where first bit is not set
        data.copyOfRange(0, lastTagByteIndex + 1)
    } else {
        ubyteArrayOf(data[0])
    }
    val tag = Asn1Tag(tagBytes)
    val len = data[tag.size]
    val (numberLengthBytes: Int, dataLength: Int) = if (len < 128u) {
        Pair(0, len.toInt())
    } else {
        // first bit is set to indicate that this byte describes how many bytes are used to encode data length
        val numberLengthBytes = (len - 128u).toInt()
        var dataLength: Int = 0
        for (i in 0..<numberLengthBytes) {
            // 1st data byte: tag, 2nd byte: number bytes required for data length
            dataLength = dataLength or (data[tag.size + numberLengthBytes - i].toInt() and 0xff shl (i * 8))
        }
        Pair(numberLengthBytes, dataLength)
    }
    val startOffset = tag.size + 1 + numberLengthBytes
    return ParsedData(tag, numberLengthBytes, dataLength, data.copyOfRange(startOffset, startOffset + dataLength))
}

@OptIn(ExperimentalUnsignedTypes::class)
private data class ParsedData(
    val tag: Asn1Tag,
    val numberLengthBytes: Int,
    val dataLength: Int,
    val data: UByteArray
)