package de.connect2x.qca.nfc.card.pace

import io.kotest.matchers.shouldBe
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)

class KeyDerivationFunctionTest {
    @Test
    fun testGetAES128Key() {
        KeyDerivationFunction.getAES128Key("313233313233".hexToByteArray(), KeyDerivationFunction.Mode.PASSWORD)
            .toHexString() shouldBe
                "e9c1a4bf6e88dd00e80ed4dfe7d19154"

        KeyDerivationFunction.getAES128Key(
            "999a75e8433c89d35e41113f93598a760492ae96c33480e6a15b8438003dbba0".hexToByteArray(),
            KeyDerivationFunction.Mode.ENC
        )
            .toHexString() shouldBe
                "7a69f2e69fd88d5a5ed8eb5fb669e869"

        KeyDerivationFunction.getAES128Key(
            "999a75e8433c89d35e41113f93598a760492ae96c33480e6a15b8438003dbba0".hexToByteArray(),
            KeyDerivationFunction.Mode.MAC
        )
            .toHexString() shouldBe
                "77be4499818017cb11161c8e5f661dcf"
    }
}