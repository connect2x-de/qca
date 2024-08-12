package de.connect2x.qca.nfc.card.pace

import de.connect2x.qca.nfc.card.apdu.CommandApdu
import de.connect2x.qca.nfc.card.apdu.ResponseApdu
import io.kotest.assertions.assertSoftly
import io.kotest.matchers.shouldBe
import kotlin.experimental.or
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class PaceKeyTest {
    @Test
    fun testEncode() {
        val paceKey = PaceKey(
            encryptionKey = "4c6d468f6aae27173b36e8acb8f061a8".hexToByteArray(),
            macKey = "15e5cad8542566d6feccea937de9e3b0".hexToByteArray(),
            secureMessagingSSC = "00000000000000000000000000000016".hexToByteArray()
        )
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6.toByte(),
            data = "840186800100".hexToByteArray(),
            initialNe = -1,
            mapOf(),
            isExtendedLengthSupported = true,
            maxTransceiveLength = 2048,
        )
        val encryptedApdu = paceKey.encrypt(commandApdu, true, 2048)
        assertSoftly(encryptedApdu) {
            cla shouldBe (commandApdu.cla or 0x0C)
            ins shouldBe commandApdu.ins
            p1 shouldBe commandApdu.p1
            p2 shouldBe commandApdu.p2
            data?.toHexString() shouldBe "871101cab7afda94f09eebce47420449fd09498e0837667ace102a9fe6"
            ne shouldBe 256
        }
    }

    @Test
    fun testDecode() {
        val paceKey = PaceKey(
            encryptionKey = "99b39b0c66449fd43fc622edefb9e499".hexToByteArray(),
            macKey = "973581ad9e26deff1848f54347eb28ea".hexToByteArray(),
            secureMessagingSSC = "00000000000000000000000000000019".hexToByteArray()
        )
        val responseApdu = ResponseApdu(
            apdu = "875101d3d9627f6b8231e87f519c07c5735c76c2df4ff29098a6ba229d000825d5ff426a5cb3592087224c0a85cd7be1d10994fb19437b566488672ae17d2fc6eb41769be83794f632b756a2bc3d80e87e1bc1990290008e083f17537d6212804c9000".hexToByteArray(),
            mapOf(),
        )
        paceKey.decrypt(responseApdu)
            .toHexString() shouldBe
                "3b31ca7824d64f9be328caabd4559eb920f0e92e5afd0ba551736f4f819d340555607ee806208d627e2f4c7b9883ebbc4055d771705436d0b20718914c7867a49000"
    }
}