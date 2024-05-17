package de.connect2x.qca.crypto.asn1

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString

actual object Asn1 {
    actual fun toObjectIdentifier(oid: String): ByteArray = ASN1ObjectIdentifier(oid).encoded

    actual fun toOctetString(data: ByteArray): ByteArray = DEROctetString(data).encoded

}