package de.connect2x.qca.idp.jose

import okio.ByteString

fun ByteString.base64UrlUnpadded(): String = base64Url().substringBefore("=")