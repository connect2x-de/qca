package de.connect2x.qca.nfc.card.pace

import io.kotest.matchers.shouldBe
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class PaceMacTest {
    @Test
    fun testCreateAsn1AuthToken() {
        val publicKey =
            "049eefa6d7dedfa9c0ec29df3c8000aa824a3befa3de286402dd945645ee92b35327ad086f329126604871cba94468bc0819edcfe8ff451536c560e8dc37a5eef6".hexToByteArray()
        createAsn1AuthToken(publicKey).toHexString() shouldBe
                "7f494f060a04007f000702020402028641049eefa6d7dedfa9c0ec29df3c8000aa824a3befa3de286402dd945645ee92b35327ad086f329126604871cba94468bc0819edcfe8ff451536c560e8dc37a5eef6"
    }

    @Test
    fun testDeriveMacToken() {
        val publicKey =
            "0448af0098ca2ee3c753332daabc14073a7f1583751d119736d0922d684cc39868932392287208541d62fd852d3989f5335c00f19c6c47b621af03893be4d028b2".hexToByteArray()
        val paceKey = "82e050473a15fdff75d57d004a97a5fa".hexToByteArray()
        publicKey.paceMac(paceKey).toHexString() shouldBe "314e51b53252a366"
    }
}