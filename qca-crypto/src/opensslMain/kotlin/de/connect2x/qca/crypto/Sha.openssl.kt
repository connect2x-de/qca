package de.connect2x.qca.crypto

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import org.openssl.*

actual fun ByteArray.sha256(): ByteArray =
    withFree {
        val digest = EVP_MD_fetch(null, "SHA256", null).checkNotNullError().freeAfter(::EVP_MD_free)
        val context = EVP_MD_CTX_new().checkNotNullError().freeAfter(::EVP_MD_CTX_free)
        val digestSize = EVP_MD_get_size(digest)
        val result = ByteArray(digestSize)

        EVP_DigestInit(context, digest).checkError()
        asUByteArray().usePinned { pinnedInput ->
            EVP_DigestUpdate(context, pinnedInput.addressOf(0), size.convert()).checkError()
        }
        result.asUByteArray().usePinned { pinnedDigest ->
            EVP_DigestFinal(context, pinnedDigest.addressOf(0), null).checkError()
        }
        result
    }