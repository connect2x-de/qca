package de.connect2x.qca.idp.jose

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

class Header(delegate: Map<String, JsonElement>) : Map<String, JsonElement> by delegate {
    constructor(
        type: String? = null,
        contentType: String? = null,
        algorithm: String? = null,
        keyId: String? = null,
        x509CertificateUrl: String? = null,
        x509CertificateChain: List<String>? = null,
        x509CertificateSha1Thumbprint: String? = null,
        x509CertificateSha256Thumbprint: String? = null,
    ) : this(
        buildMap {
            if (type != null) put("typ", JsonPrimitive(type))
            if (contentType != null) put("cty", JsonPrimitive(contentType))
            if (algorithm != null) put("alg", JsonPrimitive(algorithm))
            if (keyId != null) put("kid", JsonPrimitive(keyId))
            if (x509CertificateUrl != null) put("x5u", JsonPrimitive(x509CertificateUrl))
            if (x509CertificateChain != null) put("x5c", JsonArray(x509CertificateChain.map { JsonPrimitive(it) }))
            if (x509CertificateSha1Thumbprint != null) put("x5t", JsonPrimitive(x509CertificateSha1Thumbprint))
            if (x509CertificateSha256Thumbprint != null)
                put("x5t#S256", JsonPrimitive(x509CertificateSha256Thumbprint))
        }
    )

    val type: String?
        get() = (get("typ") as? JsonPrimitive)?.contentOrNull
    val contentType: String?
        get() = (get("cty") as? JsonPrimitive)?.contentOrNull
    val algorithm: String?
        get() = (get("alg") as? JsonPrimitive)?.contentOrNull
    val keyId: String?
        get() = (get("kid") as? JsonPrimitive)?.contentOrNull
    val x509CertificateUrl: String?
        get() = (get("x5u") as? JsonPrimitive)?.contentOrNull
    val x509CertificateChain: List<String>?
        get() = (get("x5c") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
    val x509CertificateSha1Thumbprint: String?
        get() = (get("x5t") as? JsonPrimitive)?.contentOrNull
    val x509CertificateSha256Thumbprint: String?
        get() = (get("x5t#S256") as? JsonPrimitive)?.contentOrNull
}