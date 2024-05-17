@file:OptIn(ExperimentalForeignApi::class)

package de.connect2x.qca.crypto.asn1

import de.connect2x.qca.crypto.checkError
import de.connect2x.qca.crypto.checkNotNullError
import de.connect2x.qca.crypto.withFree
import kotlinx.cinterop.*
import org.openssl.*

actual object Asn1 {
    actual fun toObjectIdentifier(oid: String): ByteArray = withFree {
        memScoped {
            val objectIdentifier = OBJ_txt2obj(oid, 1).checkNotNullError().freeAfter(::ASN1_OBJECT_free)

            val outRef = nativeHeap.alloc<CPointerVar<UByteVar>>()
            val result = i2d_ASN1_OBJECT(objectIdentifier, outRef.ptr).checkError()

            outRef.value?.let { safeBuffer ->
                UByteArray(result) {
                    safeBuffer[it]
                }
            }?.asByteArray() ?: throw IllegalStateException("Encoding failed")
        }
    }

    actual fun toOctetString(data: ByteArray): ByteArray = withFree {
        val octetString = ASN1_OCTET_STRING_new().checkNotNullError().freeAfter(::ASN1_OCTET_STRING_free)
        memScoped {
            data.asUByteArray().usePinned { pinnedData ->
                ASN1_OCTET_STRING_set(octetString, pinnedData.addressOf(0), data.size).checkError()
            }
            val outRef = nativeHeap.alloc<CPointerVar<UByteVar>>()
            val result = i2d_ASN1_OCTET_STRING(octetString, outRef.ptr)
            if (result < 0) {
                println("Octet string could not be encoded.")
                throw IllegalStateException("Octet string could not be encoded.")
            }
            val outRefValue = checkNotNull(outRef.value)
            val der = UByteArray(result) {
                outRefValue[it]
            }

            der.asByteArray()
        }
    }
}