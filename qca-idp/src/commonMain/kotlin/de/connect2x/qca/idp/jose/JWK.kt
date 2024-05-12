package de.connect2x.qca.idp.jose

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

@Serializable(with = JWKSerializer::class)
class JWK(delegate: Map<String, JsonElement>) : Map<String, JsonElement> by delegate {
    constructor(
        vararg entries: Pair<String, JsonElement>,
        keyType: String? = null,
        keyOps: List<String>? = null,
        keyId: String? = null,
        algorithm: String? = null,
        x509CertificateUrl: String? = null,
        x509CertificateChain: List<String>? = null,
        x509CertificateSha1Thumbprint: String? = null,
        x509CertificateSha256Thumbprint: String? = null,
    ) : this(
        buildMap {
            putAll(entries)
            if (keyType != null) put("kty", JsonPrimitive(keyType))
            if (keyOps != null) put("key_ops", JsonArray(keyOps.map { JsonPrimitive(it) }))
            if (algorithm != null) put("alg", JsonPrimitive(keyId))
            if (keyId != null) put("kid", JsonPrimitive(keyId))
            if (x509CertificateUrl != null) put("x5u", JsonPrimitive(x509CertificateUrl))
            if (x509CertificateChain != null) put("x5c", JsonArray(x509CertificateChain.map { JsonPrimitive(it) }))
            if (x509CertificateSha1Thumbprint != null) put("x5t", JsonPrimitive(x509CertificateSha1Thumbprint))
            if (x509CertificateSha256Thumbprint != null)
                put("x5t#S256", JsonPrimitive(x509CertificateSha256Thumbprint))
        }
    )

    val keyType: String?
        get() = (get("kty") as? JsonPrimitive)?.contentOrNull
    val keyOps: List<String>?
        get() = (get("key_ops") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
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

    override fun toString(): String = "JWK(${this})"
}

internal object JWKSerializer : KSerializer<JWK> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("JWKSerializer")

    override fun deserialize(decoder: Decoder): JWK {
        require(decoder is JsonDecoder)
        return JWK(decoder.json.decodeFromJsonElement<Map<String, JsonElement>>(decoder.decodeJsonElement()))
    }

    override fun serialize(encoder: Encoder, value: JWK) {
        require(encoder is JsonEncoder)
        encoder.encodeJsonElement(encoder.json.encodeToJsonElement<Map<String, JsonElement>>(value))
    }
}