package de.connect2x.qca.crypto

import kotlinx.cinterop.*

internal inline fun <reified T : CVariable> NativePlacement.allocArrayOf(vararg elements: CValue<T>): CArrayPointer<T> {
    val array = allocArray<T>(elements.size)
    elements.forEachIndexed { index, element -> array[index] = element }
    return array
}

internal inline operator fun <reified T : CVariable> CArrayPointer<T>.set(index: Int, value: CValue<T>) {
    value.place(get(index).ptr)
}