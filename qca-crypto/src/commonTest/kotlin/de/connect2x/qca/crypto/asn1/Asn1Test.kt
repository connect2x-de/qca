package de.connect2x.qca.crypto.asn1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@OptIn(ExperimentalUnsignedTypes::class)
class Asn1Test {

    @Test
    fun testToObjectIdentifier() {
        val oidRaw = "0.4.0.127.0.7.2.2.4.2.2"
        val oid = Asn1.toObjectIdentifier(oidRaw)
        assertContentEquals(oid, ubyteArrayOf(6u, 10u, 4u, 0u, 127u, 0u, 7u, 2u, 2u, 4u, 2u, 2u))
    }


    @Test
    fun testToOctetString() {
        val der = Asn1.toOctetString(ubyteArrayOf((0x02u + 0x00u).toUByte()))
        assertContentEquals(der, ubyteArrayOf(4u, 1u, 2u))
    }

    @Test
    fun testDerLengthBytes() {
        val testCases = arrayOf(
            Pair(2365523, ubyteArrayOf(131u, 36u, 24u, 83u)),
            Pair(127, ubyteArrayOf(127u)),
            Pair(128, ubyteArrayOf(129u, 128u))
        )
        testCases.forEach { (dataSize, expectedValue) ->
            assertContentEquals(Asn1.derLengthBytes(dataSize), expectedValue)
        }
    }

    @Test
    fun testDerEncodeWithTagAndLengthBytes() {
        val tag = Asn1Tag(ubyteArrayOf(0x7cu))
        val highTag = Asn1Tag(ubyteArrayOf(0x7fu, 0x49u))
        val testCases = arrayOf(
            Triple(
                tag,
                UByteArray(2365523) { 42u },
                tag.rawBytes + ubyteArrayOf(131u, 36u, 24u, 83u) + UByteArray(2365523) { 42u }),
            Triple(tag, UByteArray(127) { 23u }, tag.rawBytes + ubyteArrayOf(127u) + UByteArray(127) { 23u }),
            Triple(tag, UByteArray(128) { 42u }, tag.rawBytes + ubyteArrayOf(129u, 128u) + UByteArray(128) { 42u }),
            Triple(
                highTag,
                UByteArray(128) { 42u },
                highTag.rawBytes + ubyteArrayOf(129u, 128u) + UByteArray(128) { 42u })
        )
        testCases.forEach { (tagToEncode, data, expectedData) ->
            assertContentEquals(Asn1.derEncodeWithTagAndLengthBytes(tagToEncode, data), expectedData)
        }
    }

    @Test
    fun testDerDecode() {
        val tag = Asn1Tag(ubyteArrayOf(0x5Cu))
        val highTag = Asn1Tag(ubyteArrayOf(0x5Fu, 0x86u, 0xD7u, 0x3Au))

        val testCases = arrayOf(
            Triple(
                tag,
                tag.rawBytes + ubyteArrayOf(131u, 36u, 24u, 83u) + UByteArray(2365523) { 42u },
                Asn1Node(tag, Asn1Node.Content.Primitive(UByteArray(2365523) { 42u }))
            ),
            Triple(
                tag,
                tag.rawBytes + ubyteArrayOf(127u) + UByteArray(127) { 23u },
                Asn1Node(tag, Asn1Node.Content.Primitive(UByteArray(127) { 23u }))
            ),
            Triple(
                tag,
                tag.rawBytes + ubyteArrayOf(129u, 128u) + UByteArray(128) { 42u },
                Asn1Node(tag, Asn1Node.Content.Primitive(UByteArray(128) { 42u }))
            ),
            Triple(
                highTag,
                highTag.rawBytes + ubyteArrayOf(131u, 36u, 24u, 83u) + UByteArray(2365523) { 42u },
                Asn1Node(highTag, Asn1Node.Content.Primitive(UByteArray(2365523) { 42u }))
            ),
            Triple(
                highTag,
                highTag.rawBytes + ubyteArrayOf(127u) + UByteArray(127) { 23u },
                Asn1Node(highTag, Asn1Node.Content.Primitive(UByteArray(127) { 23u }))
            ),
            Triple(
                highTag,
                highTag.rawBytes + ubyteArrayOf(129u, 128u) + UByteArray(128) { 42u },
                Asn1Node(highTag, Asn1Node.Content.Primitive(UByteArray(128) { 42u }))
            ),
            Triple(constructedTag, constructedTag.rawBytes + ubyteArrayOf(22u) + constructedData, constructedNode)
        )
        testCases.forEach { (expectedTag, data, expectedData) ->
            assertEquals(Asn1.derDecode(expectedTag, data), expectedData)
        }
    }

    @Test
    fun testDerEncodeDecode() {
        assertEquals(
            Asn1.derDecode(Asn1.derEncodeWithTagAndLengthBytes(constructedTag, constructedData)),
            constructedNode
        )
    }

    private val constructedTag = Asn1Tag(ubyteArrayOf(239u))
    private val constructedData = ubyteArrayOf(
        192u, 3u, 2u, 0u, 0u, 224u, 10u, 194u, 3u, 16u, 68u, 69u, 196u, 3u,
        1u, 0u, 0u, 197u, 3u, 2u, 0u, 0u
    )
    private val constructedNode = Asn1Node(
        constructedTag, Asn1Node.Content.Constructed(
            arrayOf(
                Asn1Node(
                    Asn1Tag(ubyteArrayOf(192u)), Asn1Node.Content.Primitive(
                        ubyteArrayOf(2u, 0u, 0u)
                    )
                ),
                Asn1Node(
                    Asn1Tag(ubyteArrayOf(224u)), Asn1Node.Content.Constructed(
                        arrayOf(
                            Asn1Node(
                                Asn1Tag(ubyteArrayOf(194u)), Asn1Node.Content.Primitive(
                                    ubyteArrayOf(
                                        16u, 68u, 69u
                                    )
                                )
                            ), Asn1Node(
                                Asn1Tag(ubyteArrayOf(196u)), Asn1Node.Content.Primitive(ubyteArrayOf(1u, 0u, 0u))
                            )
                        )
                    )
                ),
                Asn1Node(
                    Asn1Tag(ubyteArrayOf(197u)), Asn1Node.Content.Primitive(
                        ubyteArrayOf(2u, 0u, 0u)
                    )
                )
            )
        )
    )
}