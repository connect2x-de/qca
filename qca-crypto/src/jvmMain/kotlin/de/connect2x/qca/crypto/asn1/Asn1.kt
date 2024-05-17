package de.connect2x.qca.crypto.asn1

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString

actual object Asn1 {
    actual fun toObjectIdentifier(oid: String): UByteArray = ASN1ObjectIdentifier(oid).encoded.asUByteArray()

    actual fun toOctetString(data: UByteArray): UByteArray = DEROctetString(data.asByteArray()).encoded.asUByteArray()

}