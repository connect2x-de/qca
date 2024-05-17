package de.connect2x.qca.crypto

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.Cipher.ENCRYPT_MODE
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

actual fun ByteArray.encryptAes256Gcm(
    key: ByteArray,
    initializationVector: ByteArray,
    authenticationData: ByteArray?,
): ByteArray =
    aes(
        mode = ENCRYPT_MODE,
        algorithm = "GCM/NoPadding",
        key = key,
        algorithmParameterSpec = GCMParameterSpec(128, initializationVector),
        authenticationData = authenticationData
    )

actual fun ByteArray.encryptAes128Ecb(
    key: ByteArray,
): ByteArray =
    aes(
        mode = ENCRYPT_MODE,
        algorithm = "ECB/NoPadding",
        key = key,
    )

actual fun ByteArray.encryptAes128Cbc(
    key: ByteArray,
    initializationVector: ByteArray,
): ByteArray =
    aes(
        mode = ENCRYPT_MODE,
        algorithm = "CBC/NoPadding",
        key = key,
        algorithmParameterSpec = IvParameterSpec(initializationVector)
    )

actual fun ByteArray.decryptAes128Cbc(
    key: ByteArray,
    initializationVector: ByteArray,
): ByteArray =
    aes(
        mode = DECRYPT_MODE,
        algorithm = "CBC/NoPadding",
        key = key,
        algorithmParameterSpec = IvParameterSpec(initializationVector)
    )

private fun ByteArray.aes(
    mode: Int,
    algorithm: String,
    key: ByteArray,
    algorithmParameterSpec: AlgorithmParameterSpec? = null,
    authenticationData: ByteArray? = null,
): ByteArray {
    val cipher = Cipher.getInstance("AES/$algorithm")
    val keySpec = SecretKeySpec(key, "AES")
    cipher.init(mode, keySpec, algorithmParameterSpec)
    if (authenticationData != null && authenticationData.isNotEmpty())
        cipher.updateAAD(authenticationData)
    return cipher.doFinal(this)
}

private const val MAC_SIZE = 8

actual fun ByteArray.deriveAes128CbcCmac(
    key: ByteArray,
): ByteArray {
    val cMac = CMac(AESEngine.newInstance())
    cMac.init(KeyParameter(key))

    cMac.update(this, 0, size)
    return ByteArray(cMac.macSize).apply {
        cMac.doFinal(this, 0)
    }.copyOfRange(0, MAC_SIZE)
}