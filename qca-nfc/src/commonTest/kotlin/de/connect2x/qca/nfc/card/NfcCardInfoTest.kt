@file:OptIn(ExperimentalUnsignedTypes::class)

package de.connect2x.qca.nfc.card

import kotlin.test.Test
import kotlin.test.assertEquals

class NfcCardInfoTest {
    @Test
    fun testParseCardGenerationVersion() {
        assertEquals(CardGeneration.from(0), CardGeneration.G1)
        assertEquals(CardGeneration.from(30002), CardGeneration.G1)
        assertEquals(CardGeneration.from(30003), CardGeneration.G1P)
        assertEquals(CardGeneration.from(39999), CardGeneration.G1P)
        assertEquals(CardGeneration.from(40000), CardGeneration.G2)
        assertEquals(CardGeneration.from(40399), CardGeneration.G2)
        assertEquals(CardGeneration.from(40400), CardGeneration.G2_1)
        assertEquals(CardGeneration.from(50000), CardGeneration.G2_1)
        assertEquals(CardGeneration.from(-1), CardGeneration.UNKNOWN)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun testParseCardGenerationParsing() {
        assertEquals(CardGeneration.from(ubyteArrayOf(0x0u, 0x0u, 0x0u).toByteArray()), CardGeneration.G1)
        assertEquals(CardGeneration.from(ubyteArrayOf(0x3u, 0x00u, 0x02u).toByteArray()), CardGeneration.G1)
        assertEquals(CardGeneration.from(ubyteArrayOf(0x3u, 0x00u, 0x03u).toByteArray()), CardGeneration.G1P)
        assertEquals(CardGeneration.from(ubyteArrayOf(0x3u, 0x63u, 0x63u).toByteArray()), CardGeneration.G1P)
        assertEquals(CardGeneration.from(ubyteArrayOf(0x4u, 0x00u, 0x00u).toByteArray()), CardGeneration.G2)
        assertEquals(CardGeneration.from(ubyteArrayOf(0x4u, 0x03u, 0x63u).toByteArray()), CardGeneration.G2)
        assertEquals(CardGeneration.from(ubyteArrayOf(0x4u, 0x04u, 0x00u).toByteArray()), CardGeneration.G2_1)
        assertEquals(CardGeneration.from(ubyteArrayOf(0x5u, 0x00u, 0x00u).toByteArray()), CardGeneration.G2_1)
        assertEquals(CardGeneration.from(byteArrayOf()), CardGeneration.UNKNOWN)
    }
}