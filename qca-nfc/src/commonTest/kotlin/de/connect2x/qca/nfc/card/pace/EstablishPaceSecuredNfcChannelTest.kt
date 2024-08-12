package de.connect2x.qca.nfc.card.pace

import de.connect2x.qca.crypto.BrainpoolP256r1Key
import de.connect2x.qca.nfc.card.NfcChannel
import de.connect2x.qca.nfc.card.pace.EstablishPaceSecuredNfcChannel.step0
import de.connect2x.qca.nfc.card.pace.EstablishPaceSecuredNfcChannel.step1
import de.connect2x.qca.nfc.card.pace.EstablishPaceSecuredNfcChannel.step2
import de.connect2x.qca.nfc.card.pace.EstablishPaceSecuredNfcChannel.step3
import de.connect2x.qca.nfc.card.pace.EstablishPaceSecuredNfcChannel.step4
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.test.runTest
import kotlin.test.Test

@OptIn(ExperimentalStdlibApi::class)
class EstablishPaceSecuredNfcChannelTest {
    private open class NfcChannelMock(
        override val isExtendedLengthSupported: Boolean = false,
        override val maxTransceiveLength: Int = 255,
    ) : NfcChannel {
        var transmitInput: ByteArray = ByteArray(0)
        var transmitReturn: ByteArray = ByteArray(0)
        override suspend fun transmit(input: ByteArray): ByteArray {
            transmitInput = input
            return transmitReturn
        }
    }

    @Test
    fun shouldStep0() = runTest {
        val nfcChannel = NfcChannelMock()
        nfcChannel.transmitReturn = "9000".hexToByteArray()
        with(nfcChannel) {
            step0()
        }
        nfcChannel.transmitInput.toHexString() shouldBe "0022c1a40f800a04007f00070202040202830102"
    }

    @Test
    fun shouldStep1() = runTest {
        val nfcChannel = NfcChannelMock()
        nfcChannel.transmitReturn = "7c12801002239ad086d05b635ab47ae1200313729000".hexToByteArray()
        val result = with(nfcChannel) {
            step1("123123")
        }
        nfcChannel.transmitInput.toHexString() shouldBe "10860000027c0000"
        result.toHexString() shouldBe "ade221ba829f0831b21c241db1496874"
    }

    @Test
    fun shouldStep2() = runTest {
        val nfcChannel = NfcChannelMock()
        nfcChannel.transmitReturn =
            "7c4382410402338ec9615bdd450f8011e0521e13110668518f16d5326c2b580954b097cb202bdcb5744814789f8c1cef81b8da5401f6ba2764b2a9144f120679223e4ac7949000".hexToByteArray()
        val result = with(nfcChannel) {
            step2(
                "25c6798f8070f49840e1f6a859c63e20".hexToByteArray(),
                keyPairOne = BrainpoolP256r1Key("cc6edc91229c41adc3d36534fd034f353c309188bb9eff3be075ac5f2e09e195".hexToByteArray()),
                keyPairTwo = BrainpoolP256r1Key("b0b126e3ee3f3f441ef790344e3d5e9397e899a2988878d4f921f280e594d645".hexToByteArray())
            )
        }
        nfcChannel.transmitInput.toHexString() shouldBe "10860000457c438141047d0cc023f4f17322e79997e5d79c353a4c5019c322a597ec1c756c19721d4b4720635dfc83a05242e766f42ee1beadacf37aff2a51ee7e9b80029f803bbf93b800"
        result.first.toHexString() shouldBe "04a64130f56d8f8145eac6eb5df2eee19d93948eff4a2238c148ee72f56ba221842782d4adc719957b873c6d5e15d37fc14fab63eaff04192d9e1d7335c2ddab30"
        result.second.privateKey.toHexString() shouldBe "b0b126e3ee3f3f441ef790344e3d5e9397e899a2988878d4f921f280e594d645"
    }

    @Test
    fun shouldStep3() = runTest {
        val nfcChannel = NfcChannelMock()
        nfcChannel.transmitReturn =
            "7c438441045b75992927235223f537b4f56d4e7749cad1150e01e658f072ee256c5e4169fb964a15ccebdd64e60a66d1371004b0a1941c0c5edddc601ea6c5e822e5493f519000".hexToByteArray()
        val result = with(nfcChannel) {
            step3(
                "049cfa47b48e4c5ff10eee1e7fdb45683c59ebbca8c61839d54dca5c7ae3ee92f087610733e8a8d83a24d3a1727e4060cd3154556d7e9b241862665de69c26accb".hexToByteArray(),
                BrainpoolP256r1Key("29369e389a0251ca778f6273d810fc1def10b2ea61abc1f3dd58bd5f54306aaa".hexToByteArray())
            )
        }
        nfcChannel.transmitInput.toHexString() shouldBe "10860000457c438341049cfa47b48e4c5ff10eee1e7fdb45683c59ebbca8c61839d54dca5c7ae3ee92f087610733e8a8d83a24d3a1727e4060cd3154556d7e9b241862665de69c26accb00"
        result.first.toHexString() shouldBe "049cfa47b48e4c5ff10eee1e7fdb45683c59ebbca8c61839d54dca5c7ae3ee92f087610733e8a8d83a24d3a1727e4060cd3154556d7e9b241862665de69c26accb"
        result.second.toHexString() shouldBe "045b75992927235223f537b4f56d4e7749cad1150e01e658f072ee256c5e4169fb964a15ccebdd64e60a66d1371004b0a1941c0c5edddc601ea6c5e822e5493f51"
        result.third.encryptionKey.toHexString() shouldBe "776be6866976ff9a8e9b1aff0638db91"
        result.third.macKey.toHexString() shouldBe "2f4f28fabcaeaaf790a8306defb4d60e"
    }

    @Test
    fun shouldStep4() = runTest {
        val nfcChannel = NfcChannelMock()
        nfcChannel.transmitReturn = "7c0a8608de306b129fa7e95a9000".hexToByteArray()
        val result = with(nfcChannel) {
            step4(
                "049cfa47b48e4c5ff10eee1e7fdb45683c59ebbca8c61839d54dca5c7ae3ee92f087610733e8a8d83a24d3a1727e4060cd3154556d7e9b241862665de69c26accb".hexToByteArray(),
                "045b75992927235223f537b4f56d4e7749cad1150e01e658f072ee256c5e4169fb964a15ccebdd64e60a66d1371004b0a1941c0c5edddc601ea6c5e822e5493f51".hexToByteArray(),
                PaceKey(
                    "776be6866976ff9a8e9b1aff0638db91".hexToByteArray(),
                    "2f4f28fabcaeaaf790a8306defb4d60e".hexToByteArray()
                )
            )
        }
        nfcChannel.transmitInput.toHexString() shouldBe "008600000c7c0a850841ceab1a2931933e00"
    }
}