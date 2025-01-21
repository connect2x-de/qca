package de.connect2x.qca.encoding

import com.ionspin.kotlin.bignum.integer.toBigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

@OptIn(ExperimentalUnsignedTypes::class)
class FileControlParameterTest {
    @Test
    fun test1() {
        assertEquals(
            FileControlParameter(
                size = 3000.toBigInteger(),
                fileDescriptor = FileControlParameter.FileDescriptor.TransparentEF,
                fileIdentifier = 50438u,
                applicationIdentifier = emptyList(),
                shortFileIdentifier = 48u,
                lifeCycleStatus = FileControlParameter.LifecycleStatus.OPERATIONAL_ACTIVE,
                profileIdentifier = null,
                readSize = 880.toBigInteger(),
            ),
            FileControlParameter.decodeFromDer(ubyteArrayOf(
                0x62u, 0x15u, 0x83u, 0x02u, 0xc5u, 0x06u, 0x8au, 0x01u, 0x05u, 0x82u, 0x01u, 0x41u, 0x88u, 0x01u,
                0x30u, 0x80u, 0x02u, 0x0bu, 0xb8u, 0xc5u, 0x02u, 0x03u, 0x70u,
            ).toByteArray())
        )
    }

    @Test
    fun test2() {
        assertEquals(
            FileControlParameter(
                size = 3000.toBigInteger(),
                fileDescriptor = FileControlParameter.FileDescriptor.TransparentEF,
                fileIdentifier = 50438u,
                applicationIdentifier = emptyList(),
                shortFileIdentifier = 48u,
                lifeCycleStatus = FileControlParameter.LifecycleStatus.OPERATIONAL_ACTIVE,
                profileIdentifier = null,
                readSize = 870.toBigInteger(),
            ),
            FileControlParameter.decodeFromDer(ubyteArrayOf(
                0x62u, 0x15u, 0x83u, 0x02u, 0xc5u, 0x06u, 0x8au, 0x01u, 0x05u, 0x82u, 0x01u, 0x41u, 0x88u, 0x01u,
                0x30u, 0x80u, 0x02u, 0x0bu, 0xb8u, 0xc5u, 0x02u, 0x03u, 0x66u,
            ).toByteArray())
        )
    }

    @Test
    fun test3() {
        assertEquals(
            FileControlParameter(
                size = 3000.toBigInteger(),
                fileDescriptor = FileControlParameter.FileDescriptor.TransparentEF,
                fileIdentifier = 50438u,
                applicationIdentifier = emptyList(),
                shortFileIdentifier = 48u,
                lifeCycleStatus = FileControlParameter.LifecycleStatus.OPERATIONAL_ACTIVE,
                profileIdentifier = null,
                readSize = 934.toBigInteger(),
            ),
            FileControlParameter.decodeFromDer(ubyteArrayOf(
                0x62u, 0x15u, 0x83u, 0x02u, 0xc5u, 0x06u, 0x8au, 0x01u, 0x05u, 0x82u, 0x01u, 0x41u, 0x88u, 0x01u,
                0x30u, 0x80u, 0x02u, 0x0bu, 0xb8u, 0xc5u, 0x02u, 0x03u, 0xa6u,
            ).toByteArray())
        )
    }

    @Test
    fun test4() {
        assertEquals(
            FileControlParameter(
                size = 3000.toBigInteger(),
                fileDescriptor = FileControlParameter.FileDescriptor.TransparentEF,
                fileIdentifier = 50438u,
                applicationIdentifier = emptyList(),
                shortFileIdentifier = 48u,
                lifeCycleStatus = FileControlParameter.LifecycleStatus.OPERATIONAL_ACTIVE,
                profileIdentifier = null,
                readSize = 910.toBigInteger(),
            ),
            FileControlParameter.decodeFromDer(ubyteArrayOf(
                0x62u, 0x15u, 0x83u, 0x02u, 0xc5u, 0x06u, 0x8au, 0x01u, 0x05u, 0x82u, 0x01u, 0x41u, 0x88u, 0x01u,
                0x30u, 0x80u, 0x02u, 0x0bu, 0xb8u, 0xc5u, 0x02u, 0x03u, 0x8eu,
            ).toByteArray())
        )
    }

    @Test
    fun test5() {
        assertEquals(
            FileControlParameter(
                size = 3000.toBigInteger(),
                fileDescriptor = FileControlParameter.FileDescriptor.TransparentEF,
                fileIdentifier = 50438u,
                applicationIdentifier = emptyList(),
                shortFileIdentifier = 48u,
                lifeCycleStatus = FileControlParameter.LifecycleStatus.OPERATIONAL_ACTIVE,
                profileIdentifier = null,
                readSize = 954.toBigInteger(),
            ),
            FileControlParameter.decodeFromDer(ubyteArrayOf(
                0x62u, 0x15u, 0x83u, 0x02u, 0xc5u, 0x06u, 0x8au, 0x01u, 0x05u, 0x82u, 0x01u, 0x41u, 0x88u, 0x01u,
                0x30u, 0x80u, 0x02u, 0x0bu, 0xb8u, 0xc5u, 0x02u, 0x03u, 0xbau,
            ).toByteArray())
        )
    }

    @Test
    fun test6() {
        assertEquals(
            FileControlParameter(
                size = 3000.toBigInteger(),
                fileDescriptor = FileControlParameter.FileDescriptor.TransparentEF,
                fileIdentifier = 50438u,
                applicationIdentifier = emptyList(),
                shortFileIdentifier = 48u,
                lifeCycleStatus = FileControlParameter.LifecycleStatus.OPERATIONAL_ACTIVE,
                profileIdentifier = null,
                readSize = 855.toBigInteger(),
            ),
            FileControlParameter.decodeFromDer(ubyteArrayOf(
                0x62u, 0x15u, 0x83u, 0x02u, 0xc5u, 0x06u, 0x8au, 0x01u, 0x05u, 0x82u, 0x01u, 0x41u, 0x88u, 0x01u,
                0x30u, 0x80u, 0x02u, 0x0bu, 0xb8u, 0xc5u, 0x02u, 0x03u, 0x57u,
            ).toByteArray())
        )
    }
}
