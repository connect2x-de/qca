package de.connect2x.qca.encoding

import at.asitplus.signum.indispensable.asn1.Asn1CustomStructure
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1Structure
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import com.ionspin.kotlin.bignum.integer.BigInteger

private object Tags {
    // gemSpec_COS G2_N013.900 - (N013.900) K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N013.900
    val FCP = Asn1Element.Tag(0x2u, constructed = true, tagClass = TagClass.APPLICATION)
    // gemSpec_COS G2_N014.000.a - (N014.000)a K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.000.a
    val Size = Asn1.ImplicitTag(0x0u)
    // gemSpec_COS A_13911 - (N014.100) K_COS
    // gemSpec_COS G2_N014.100.a - (N014.100)a K_COS
    // gemSpec_COS G2_N014.100.b - (N014.100)b K_COS
    // gemSpec_COS G2_N014.100.c - (N014.100)c K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#A_13911
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.100.a
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.100.b
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.100.c
    val FileDescriptor = Asn1.ImplicitTag(0x2u)
    // gemSpec_COS G2_N014.200 - (N014.200) K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.200
    val FID = Asn1.ImplicitTag(0x3u)
    // gemSpec_COS G2_N014.300 - (N014.300) K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.300
    val AID = Asn1.ImplicitTag(0x4u)
    // gemSpec_COS A_13912 - (N014.400) K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#A_13912
    val SFI = Asn1.ImplicitTag(0x8u)
    // gemSpec_COS A_13913-01 - (N014.500) K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#A_13913-01
    val LCS = Asn1.ImplicitTag(0xAu)
    // gemSpec_COS G2_N014.600.a - (N014.600)a K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.600.a
    val ProfileIdentifier = Asn1.ImplicitTag(0xFu)
    // gemSpec_COS A_13914 - (N014.700) K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#A_13914
    val ReadSize = Asn1Element.Tag(0x5u, constructed = false, tagClass = TagClass.PRIVATE)
}

// gemSpec_COS 8.3.3
// https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#8.3.3
data class FileControlParameter(
    val size: BigInteger? = null,
    val fileDescriptor: FileDescriptor? = null,
    // gemSpec_COS 8.1.1
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#8.1.1
    val fileIdentifier: UShort? = null,
    // ISO/IEC 7816-4:2005 8.2.1
    val applicationIdentifier: List<ByteArray> = emptyList(),
    // gemSpec_COS 8.1.2
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#8.1.2
    val shortFileIdentifier: UByte? = null,
    // ISO/IEC 7816-4:2005 5.3.3.2
    // gemSpec_COS 8.1.3
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#8.1.3
    val lifeCycleStatus: LifecycleStatus? = null,
    val profileIdentifier: UByte? = null,
    val readSize: BigInteger? = null,
) : Asn1Encodable<Asn1Structure> {
    override fun encodeToTlv(): Asn1Structure =
        Asn1CustomStructure(
            tag = Tags.FCP.tagValue,
            tagClass = Tags.FCP.tagClass,
            children = listOfNotNull(
                size?.let { Asn1Primitive(Tags.Size, it.toByteArray()) },
                fileDescriptor?.let { Asn1Primitive(Tags.FileDescriptor, it.toByteArray()) },
                fileIdentifier?.let { Asn1Primitive(Tags.FID, it.toByteArray()) },
                Asn1Primitive(Tags.SFI, shortFileIdentifier?.toByteArray() ?: ByteArray(0)),
                lifeCycleStatus?.let { Asn1Primitive(Tags.LCS, it.values.first().toByteArray()) },
                profileIdentifier?.let { Asn1Primitive(Tags.ProfileIdentifier, it.toByteArray()) },
                readSize?.let { Asn1Primitive(Tags.ReadSize, it.toByteArray()) },
            ) + applicationIdentifier.map { Asn1Primitive(Tags.AID, it) },
        )

    companion object : Asn1Decodable<Asn1Structure, FileControlParameter> {
        override fun doDecode(src: Asn1Structure) = FileControlParameter(
            size = src.children.find { it.tag == Tags.Size }
                ?.asPrimitive()?.content?.toBigInteger(),
            fileDescriptor = src.children.find { it.tag == Tags.FileDescriptor }
                ?.asPrimitive()?.content?.let(FileDescriptor.Companion::of),
            fileIdentifier = src.children.find { it.tag == Tags.FID }
                ?.asPrimitive()?.content?.toUShort(),
            applicationIdentifier = src.children.filter { it.tag == Tags.AID }
                .map { it.asPrimitive().content },
            shortFileIdentifier = src.children.find { it.tag == Tags.SFI }
                ?.asPrimitive()?.content?.let { if (it.isEmpty()) null else it.toUByte() },
            lifeCycleStatus = src.children.find { it.tag == Tags.LCS }
                ?.asPrimitive()?.content?.toByte()?.let(LifecycleStatus.Companion::of),
            profileIdentifier = src.children.find { it.tag == Tags.ProfileIdentifier }
                ?.asPrimitive()?.content?.toUByte(),
            readSize = src.children.find { it.tag == Tags.ReadSize }
                ?.asPrimitive()?.content?.toBigInteger(),
        )

        fun decodeFromTlvOrNull(src: Asn1Structure) = decodeFromTlvOrNull(src, Tags.FCP)
        fun decodeFromTlvSafe(src: Asn1Structure) = decodeFromTlvSafe(src, Tags.FCP)
        fun decodeFromDer(src: ByteArray) = decodeFromDer(src, Tags.FCP)
        fun decodeFromDerOrNull(src: ByteArray) = decodeFromDerOrNull(src, Tags.FCP)
        fun decodeFromDerSafe(src: ByteArray) = decodeFromDerSafe(src, Tags.FCP)
    }


    // gemSpec_COS A_13911 - (N014.100) K_COS
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#A_13911
    sealed class FileDescriptor {
        abstract fun toByteArray(): ByteArray

        // gemSpec_COS G2_N014.100.a - (N014.100)a K_COS
        // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.100.a
        data object Folder: FileDescriptor() {
            val values: List<Byte> = listOf(0x38, 0x78)
            override fun toByteArray() = byteArrayOf(values.first())
        }

        // gemSpec_COS G2_N014.100.b - (N014.100)b K_COS
        // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.100.b
        data object TransparentEF: FileDescriptor() {
            val values: List<Byte> = listOf(0x01, 0x41)
            override fun toByteArray() = byteArrayOf(Folder.values.first())
        }

        // gemSpec_COS G2_N014.100.c - (N014.100)c K_COS
        // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#G2_N014.100.c
        data class Structured(
            val type: StructuredFileType,
            val recordSize: UShort,
            val recordCount: UShort,
        ): FileDescriptor() {
            enum class StructuredFileType(vararg val values: Byte) {
                LINEAR_FIXED(0x02, 0x42),
                LINEAR_VARIABLE(0x04, 0x44),
                CYCLIC(0x06, 0x46);

                companion object {
                    fun of(value: Byte) = when (value) {
                        in LINEAR_FIXED.values -> LINEAR_FIXED
                        in LINEAR_VARIABLE.values -> LINEAR_VARIABLE
                        in CYCLIC.values -> CYCLIC
                        else -> throw IllegalArgumentException("Unknown structured file type: $value")
                    }
                }
            }
            override fun toByteArray() = byteArrayOf(
                type.values.first(),
                *recordSize.toByteArray(),
                *recordCount.toByteArray()
            )

            companion object {
                val values: List<Byte> = StructuredFileType.entries.flatMap { it.values.toList() }
            }
        }

        companion object {
            fun of(data: ByteArray): FileDescriptor =
                when (val type = data[0]) {
                    in Folder.values -> Folder
                    in TransparentEF.values -> TransparentEF
                    in Structured.values -> Structured(
                        Structured.StructuredFileType.of(type),
                        data.sliceArray(2..3).toUShort(),
                        data.sliceArray(4..5).toUShort()
                    )
                    else -> throw IllegalArgumentException("Unknown file type: $type")
                }
        }
    }

    // ISO/IEC 7816-4:2005 5.3.3.2
    // gemSpec_COS 8.1.3
    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0/#8.1.3
    enum class LifecycleStatus(vararg val values: Byte) {
        UNKNOWN(0x00),
        CREATION(0x01),
        INITIALISATION(0x03),
        OPERATIONAL_ACTIVE(0x05, 0x07),
        OPERATIONAL_DEACTIVATED(0x04, 0x06),
        TERMINATION(0x0c, 0x0d, 0x0e, 0x0f);

        companion object {
            fun of(value: Byte) = when (value) {
                in UNKNOWN.values -> UNKNOWN
                in CREATION.values -> CREATION
                in INITIALISATION.values -> INITIALISATION
                in OPERATIONAL_ACTIVE.values -> OPERATIONAL_ACTIVE
                in OPERATIONAL_DEACTIVATED.values -> OPERATIONAL_DEACTIVATED
                in TERMINATION.values -> TERMINATION
                else -> throw IllegalArgumentException("Unknown lifecycle status: $value")
            }
        }
    }
}
