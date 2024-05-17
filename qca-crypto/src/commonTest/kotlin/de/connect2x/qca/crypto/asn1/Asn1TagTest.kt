package de.connect2x.qca.crypto.asn1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@OptIn(ExperimentalUnsignedTypes::class)
class Asn1TagTest {
    private val createTagTestCases = arrayOf(
        CreateTagTestCase(Asn1Tag.TagClass.APPLICATION, 0x1C, Asn1Tag.DerEncodingForm.CONSTRUCTED, ubyteArrayOf(124u)),
        CreateTagTestCase(Asn1Tag.TagClass.APPLICATION, 0x1C, Asn1Tag.DerEncodingForm.PRIMITIVE, ubyteArrayOf(92u)),
        CreateTagTestCase(
            Asn1Tag.TagClass.CONTEXT_DEFINED,
            0x01,
            Asn1Tag.DerEncodingForm.PRIMITIVE,
            ubyteArrayOf(129u)
        ),
        CreateTagTestCase(
            Asn1Tag.TagClass.CONTEXT_DEFINED,
            0x1C,
            Asn1Tag.DerEncodingForm.CONSTRUCTED,
            ubyteArrayOf(188u)
        ),
        CreateTagTestCase(Asn1Tag.TagClass.PRIVATE, 0x1C, Asn1Tag.DerEncodingForm.PRIMITIVE, ubyteArrayOf(220u)),
        CreateTagTestCase(Asn1Tag.TagClass.PRIVATE, 0x1C, Asn1Tag.DerEncodingForm.CONSTRUCTED, ubyteArrayOf(252u)),
        CreateTagTestCase(Asn1Tag.TagClass.UNIVERSAL, 0x1C, Asn1Tag.DerEncodingForm.PRIMITIVE, ubyteArrayOf(28u)),
        CreateTagTestCase(Asn1Tag.TagClass.UNIVERSAL, 0x1C, Asn1Tag.DerEncodingForm.CONSTRUCTED, ubyteArrayOf(60u)),
        CreateTagTestCase(
            Asn1Tag.TagClass.APPLICATION,
            0x49,
            Asn1Tag.DerEncodingForm.CONSTRUCTED,
            ubyteArrayOf(127u, 0x49u)
        ),
        CreateTagTestCase(
            Asn1Tag.TagClass.APPLICATION,
            0xCD,
            Asn1Tag.DerEncodingForm.CONSTRUCTED,
            ubyteArrayOf(127u, 0x81u, 0x4Du)
        ),
        CreateTagTestCase(
            Asn1Tag.TagClass.APPLICATION,
            0x1ABBA,
            Asn1Tag.DerEncodingForm.CONSTRUCTED,
            ubyteArrayOf(127u, 0x86u, 0xD7u, 0x3Au)
        ),
    )

    @Test
    fun testCreateTag() {
        createTagTestCases.forEach { testCase ->
            val tag = Asn1Tag(testCase.tagClass, testCase.tagNumber, testCase.encodingForm)
            assertContentEquals(tag.rawBytes, testCase.tagBytes)
        }
    }

    @Test
    fun testCreateTagWithBytes() {
        createTagTestCases.forEach { testCase ->
            val tag = Asn1Tag(testCase.tagBytes)
            assertEquals(testCase.tagClass, tag.tagClass)
            assertEquals(testCase.tagNumber, tag.tagNumber)
            assertEquals(testCase.tagClass, tag.tagClass)
        }
    }

    internal data class CreateTagTestCase(
        val tagClass: Asn1Tag.TagClass,
        val tagNumber: Int,
        val encodingForm: Asn1Tag.DerEncodingForm,
        val tagBytes: UByteArray
    )

}