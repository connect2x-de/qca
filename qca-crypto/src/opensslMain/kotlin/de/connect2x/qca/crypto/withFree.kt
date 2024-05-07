package de.connect2x.qca.crypto

import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CValuesRef

class WithFree {
    private val freeOperations = mutableListOf<() -> Unit>()

    fun <T : CPointed> CValuesRef<T>.freeAfter(free: (CValuesRef<T>) -> Unit): CValuesRef<T> =
        also {
            freeOperations.add {
                free(it)
            }
        }

    @PublishedApi
    internal fun freeAll() = freeOperations.reversed().forEach { it() }
}

inline fun <T> withFree(block: WithFree.() -> T): T {
    val withFree = WithFree()
    return try {
        withFree.block()
    } finally {
        withFree.freeAll()
    }
}