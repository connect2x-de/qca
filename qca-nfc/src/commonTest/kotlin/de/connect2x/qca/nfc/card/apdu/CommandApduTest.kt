@file:OptIn(ExperimentalUnsignedTypes::class)

package de.connect2x.qca.nfc.card.apdu

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFails

class CommandApduTest {
    @Test
    fun `case 1`() {
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = null,
            initialNe = -1,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header)
    }

    @Test
    fun `case 2s`() {
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = null,
            initialNe = 3,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(commandApdu.ne.toByte()))
    }

    @Test
    fun `case 2s wildcard`() {
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = null,
            initialNe = 256,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(0))
    }

    @Test
    fun `case 2e`() {
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = null,
            initialNe = 257,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(0, 1, 1))
    }

    @Test
    fun `case 2e wildcard`() {
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = null,
            initialNe = 65536,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + ByteArray(3) { 0 })
    }

    @Test
    fun `case 3s`() {
        val data = ByteArray(255) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = -1,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(data.size.toByte()) + data)
    }

    @Test
    fun `case 3e`() {
        val data = ByteArray(256) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = -1,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(0, 1, 0) + data)
    }

    @Test
    fun `data size too big`() {
        val data = ByteArray(65536) { 23 }
        assertFails {
            CommandApdu(
                cla = 0x00,
                ins = 0x22,
                p1 = 0x41,
                p2 = 0xB6u.toByte(),
                data = data,
                initialNe = -1,
                expectedStatus = mapOf(),
                isExtendedLengthSupported = false,
                maxTransceiveLength = 2048,
            )
        }
    }

    @Test
    fun `case 4s`() {
        val data = ByteArray(255) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 255,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(
            commandApdu.apduBytes,
            header + byteArrayOf(data.size.toByte()) + data + byteArrayOf(255.toByte())
        )
    }

    @Test
    fun `case 4s ne wildcard short`() {
        val data = ByteArray(255) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 256,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(data.size.toByte()) + data + byteArrayOf(0))
    }

    @Test
    fun `case 4e ne extended`() {
        val data = ByteArray(3) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 257,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(
            commandApdu.apduBytes,
            header + byteArrayOf(0, 0, data.size.toByte()) + data + byteArrayOf(1, 1)
        )
    }

    @Test
    fun `case 4e ne extended plus wildcard`() {
        val data = ByteArray(3) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 65536,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(
            commandApdu.apduBytes,
            header + byteArrayOf(0, 0, data.size.toByte()) + data + byteArrayOf(0, 0)
        )
    }

    @Test
    fun `case 4e data size extended`() {
        val data = ByteArray(256) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 255,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(0, 1, 0) + data + byteArrayOf(0, 255.toByte()))
    }

    @Test
    fun `case 4e data size extended - ne wildcard short`() {
        val data = ByteArray(256) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 256,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(0, 1, 0) + data + byteArrayOf(1, 0))
    }

    @Test
    fun `case 4e data size and ne extended`() {
        val data = ByteArray(257) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 257,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(0, 1, 1) + data + byteArrayOf(1, 1))
    }

    @Test
    fun `case 4e data size and ne extended plus wildcard`() {
        val data = ByteArray(257) { 23 }
        val commandApdu = CommandApdu(
            cla = 0x00,
            ins = 0x22,
            p1 = 0x41,
            p2 = 0xB6u.toByte(),
            data = data,
            initialNe = 65536,
            expectedStatus = mapOf(),
            isExtendedLengthSupported = false,
            maxTransceiveLength = 2048,
        )
        val header = byteArrayOf(commandApdu.cla, commandApdu.ins, commandApdu.p1, commandApdu.p2)
        assertContentEquals(commandApdu.header, header)
        assertContentEquals(commandApdu.apduBytes, header + byteArrayOf(0, 1, 1) + data + byteArrayOf(0, 0))
    }
}