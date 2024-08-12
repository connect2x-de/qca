package de.connect2x.qca.nfc.card.pace

import okio.ByteString.Companion.toByteString

private const val AES128_LENGTH = 16
private const val OFFSET_LENGTH = 4
private const val ENC_LAST_BYTE = 1
private const val MAC_LAST_BYTE = 2
private const val PASSWORD_LAST_BYTE = 3

/**
 * This class provides functionality to derive AES-128 keys.
 */
internal object KeyDerivationFunction {
    /**
     * derive AES-128 key
     *
     * @param sharedSecretK byte array with shared secret value.
     * @param mode key derivation for ENC, MAC or derivation from password
     * @return byte array with AES-128 key
     */
    fun getAES128Key(sharedSecretK: ByteArray, mode: Mode): ByteArray {
        val data = replaceLastKeyByte(sharedSecretK, mode)
        return data.toByteString().sha1().toByteArray().copyOf(AES128_LENGTH)
    }

    private fun replaceLastKeyByte(key: ByteArray, mode: Mode): ByteArray =
        ByteArray(key.size + OFFSET_LENGTH).apply {
            key.copyInto(this)
            this[this.size - 1] = when (mode) {
                Mode.ENC -> ENC_LAST_BYTE
                Mode.MAC -> MAC_LAST_BYTE
                Mode.PASSWORD -> PASSWORD_LAST_BYTE
            }.toByte()
        }

    enum class Mode {
        ENC, // key for encryption/decryption
        MAC, // key for MAC
        PASSWORD // encryption keys from a password
    }
}