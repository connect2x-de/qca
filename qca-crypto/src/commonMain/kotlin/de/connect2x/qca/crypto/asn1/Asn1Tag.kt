package de.connect2x.qca.crypto.asn1

// TODO UByteArray -> ByteArray
@OptIn(ExperimentalUnsignedTypes::class)
data class Asn1Tag(
    val tagClass: TagClass,
    val tagNumber: Int,
    val encodingForm: DerEncodingForm,
    val rawBytes: UByteArray
) {
    // number of bytes to describe tag
    val size get() = rawBytes.size

    constructor(data: UByteArray) : this(
        tagClass = TagClass.from(data[0]),
        tagNumber = parseTagNumber(data),
        encodingForm = DerEncodingForm.from(data[0]),
        rawBytes = data
    )

    constructor(
        tagClass: TagClass,
        tagNumber: Int,
        encodingForm: DerEncodingForm
    ) : this(
        tagClass = tagClass,
        tagNumber = tagNumber,
        encodingForm = encodingForm,
        rawBytes = createByteRepresentation(tagNumber, tagClass, encodingForm)
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Asn1Tag

        return rawBytes.contentEquals(other.rawBytes)
    }

    override fun hashCode(): Int {
        return rawBytes.contentHashCode()
    }

    companion object {
        fun parseTagNumber(bytes: UByteArray): Int {
            require(bytes.isNotEmpty()) { "Invalid tag data size" }
            // check if it's a high tag number, which is the case if the last 5 bits are set
            return if (bytes[0] and 0x1fu == (0x1f).toUByte()) {
                // 8th bit of last byte mustn't be set
                require(bytes[bytes.size - 1] and 0x80u != (0x80).toUByte()) { "Malformed extended tag" }
                var tagNumber = 0
                for (i in 1..<bytes.size) {
                    tagNumber = tagNumber or ((bytes[i].toInt() and 0x7f) shl (bytes.size - 1 - i) * 7)
                }
                return tagNumber
            } else {
                bytes[0].toInt() and 0x1f
            }
        }

        fun createByteRepresentation(tagNumber: Int, tagClass: TagClass, encodingForm: DerEncodingForm) =
            if (tagNumber < 0x1f) {
                // see https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-tag-bytes
                // https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/basic-encoding-rules.html
                // ITU-T X.690#8.1.2 for tag bytes
                val tag = tagClass.flag or encodingForm.flag or tagNumber.toUByte()
                ubyteArrayOf(tag)
            } else {
                // set last 5 bits to 1 to indicate that the identifier is comprised of a leading octet followed by
                // one or more subsequent octets
                val firstByte = tagClass.flag or encodingForm.flag or 0x1fu
                var numberBytesForTag = 0
                var value = tagNumber
                do {
                    numberBytesForTag++
                    value = value shr 7
                } while (value != 0)
                val buffer = UByteArray(numberBytesForTag)
                for (i in 0..<numberBytesForTag) {
                    // set 8th bit if it's not the last
                    if (i == 0) {
                        buffer[numberBytesForTag - 1] = (tagNumber and 0x7f).toUByte()
                    } else {
                        buffer[numberBytesForTag - i - 1] = (((tagNumber shr (i * 7)) and 0x7f) or 0x80).toUByte()
                    }
                }
                ubyteArrayOf(firstByte) + buffer
            }
    }

// see https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-tag-bytes
//
//# define V_ASN1_UNIVERSAL                0x00
//# define V_ASN1_APPLICATION              0x40
//# define V_ASN1_CONTEXT_SPECIFIC         0x80
//# define V_ASN1_PRIVATE                  0xc0

//# define V_ASN1_PRIMITIVE                0x00
//# define V_ASN1_CONSTRUCTED              0x20

    enum class TagClass(val flag: UByte) {
        UNIVERSAL(0x00.toUByte()),
        APPLICATION(0x40.toUByte()),
        CONTEXT_DEFINED(0x80.toUByte()),
        PRIVATE(0xc0.toUByte());

        companion object {
            fun from(firstTagByte: UByte): TagClass {
                return when (firstTagByte and 0xc0u) {
                    UNIVERSAL.flag -> UNIVERSAL
                    APPLICATION.flag -> APPLICATION
                    CONTEXT_DEFINED.flag -> CONTEXT_DEFINED
                    else -> PRIVATE
                }
            }
        }
    }

    enum class DerEncodingForm(val flag: UByte) {
        PRIMITIVE(0x0u),
        CONSTRUCTED(0x20.toUByte());

        companion object {
            fun from(firstTagByte: UByte): DerEncodingForm {
                return when (firstTagByte and 0x20u) {
                    PRIMITIVE.flag -> PRIMITIVE
                    else -> CONSTRUCTED
                }
            }
        }
    }
}