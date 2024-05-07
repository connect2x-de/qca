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
}

private object JWKSerializer : KSerializer<JWK> {
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