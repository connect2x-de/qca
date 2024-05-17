package de.connect2x.qca.crypto.asn1

// TODO UByteArray -> ByteArray
@OptIn(ExperimentalUnsignedTypes::class)
data class Asn1Node(
    val tag: Asn1Tag,
    val content: Content,
) {

    // The content of a single `ASN1Node`.
    sealed class Content {
        // This ``ASN1Node`` is constructed, and has a number of child nodes.
        data class Constructed(val nodes: Array<Asn1Node>) : Content() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other == null || this::class != other::class) return false

                other as Constructed

                if (!nodes.contentEquals(other.nodes)) return false

                return true
            }

            override fun hashCode(): Int {
                return nodes.contentHashCode()
            }
        }

        // This `ASN1Node` is primitive, and is made up only of a collection of bytes.
        data class Primitive(val data: UByteArray) : Content() {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other == null || this::class != other::class) return false

                other as Primitive

                return data.contentEquals(other.data)
            }

            override fun hashCode(): Int {
                return data.contentHashCode()
            }
        }
    }
}