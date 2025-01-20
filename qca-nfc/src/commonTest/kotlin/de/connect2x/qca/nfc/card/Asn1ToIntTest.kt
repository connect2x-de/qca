package de.connect2x.qca.nfc.card

import de.connect2x.qca.crypto.asn1.Asn1Node
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.io.writeUByte
import kotlinx.io.writeUShort
import kotlin.test.Test
import kotlin.test.assertEquals

class Asn1ToIntTest {
    @Test
    fun testAllBytes() {
        val buffer = Buffer()
        for (i in UByte.MIN_VALUE..UByte.MAX_VALUE) {
            buffer.writeUByte(i.toUByte())
            val byteArray = buffer.readByteArray()
            val node = Asn1Node.Content.Primitive(byteArray)
            val read = node.data.toInt()
            assertEquals(i.toInt(), read)
        }
    }

    @Test
    fun testAllShorts() {
        val buffer = Buffer()
        for (i in UShort.MIN_VALUE..UShort.MAX_VALUE) {
            buffer.writeUShort(i.toUShort())
            val byteArray = buffer.readByteArray()
            val node = Asn1Node.Content.Primitive(byteArray)
            val read = node.data.toInt()
            assertEquals(i.toInt(), read)
        }
    }
}