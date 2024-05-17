package de.connect2x.qca.crypto

import io.kotest.matchers.shouldBe
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class ECUtilsTest {
    @Test
    fun shouldEncodeX962() {
        ECPointImpl(
            "0011111111".hexToByteArray(), // remove leading zero and fill to 32 Bytes
            "2222222222".hexToByteArray() // fill to 32 Bytes
        ).encodeX962()
            .toHexString() shouldBe
                "04" +
                "00000000000000000000000000000000000000000000000000000000" + "11111111" +
                "000000000000000000000000000000000000000000000000000000" + "2222222222"
    }
}