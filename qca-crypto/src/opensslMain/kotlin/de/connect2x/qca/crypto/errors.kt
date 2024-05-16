package de.connect2x.qca.crypto

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.toKString
import org.openssl.ERR_error_string
import org.openssl.ERR_get_error

internal fun <T : Any> T?.checkNotNullError(): T {
    if (this != null) return this
    error(errorMessage(0))
}

internal fun Int.checkError(): Int {
    if (this > 0) return this
    error(errorMessage(this))
}

private fun errorMessage(result: Int): String {
    val message = buildString {
        var code = ERR_get_error()
        if (code.toInt() != 0) do {
            val message = memScoped {
                val buffer = allocArray<ByteVar>(256)
                ERR_error_string(code, buffer)?.toKString()
            }
            append(message)
            code = ERR_get_error()
            if (code.toInt() != 0) append(", ")
        } while (code.toInt() != 0)
    }
    return "OPENSSL failure: $message (result: $result)"
}