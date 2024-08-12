package de.connect2x.qca.nfc.card

class NfcTagLostException(message: String? = null, cause: Throwable? = null) :
    IllegalStateException(message ?: cause?.message, cause)