package de.connect2x.qca.idp.jose

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString

@Serializable(with = JWSSerializer::class)
class JWS(
    val header: Header,
    val payload: Payload,
    val signature: ByteArray,
) {
    companion object {
        fun decodeFromString(encoded: String): JWS {
            val components =
                encoded.split(".").map { checkNotNull(it.decodeBase64()) { "could not decode base64 in JWS" } }
            check(components.size == 3) { "JWS did not contain exactly three parts" }

            return JWS(
                header = joseJson.decodeFromString(components[0].utf8()),
                payload = joseJson.decodeFromString(components[1].utf8()),
                signature = components[2].toByteArray(),
            )
        }

        suspend fun sign(header: Header, payload: Payload, sign: suspend (String) -> ByteArray): JWS {
            val signable = listOf(
                joseJson.encodeToString(header).encodeUtf8().base64UrlUnpadded(),
                joseJson.encodeToString(payload).encodeUtf8().base64UrlUnpadded(),
            ).joinToString(".")
            return JWS(
                header = header,
                payload = payload,
                signature = sign(signable)
            )
        }
    }

    fun encodeToString(): String =
        listOf(
            joseJson.encodeToString(header).encodeUtf8().base64UrlUnpadded(),
            joseJson.encodeToString(payload).encodeUtf8().base64UrlUnpadded(),
            signature.toByteString().base64UrlUnpadded()
        ).joinToString(".")

    @Serializable(with = JWSHeaderSerializer::class)
    class Header(delegate: Map<String, JsonElement>) : Map<String, JsonElement> by delegate {
        constructor(
            vararg entries: Pair<String, JsonElement>,
            type: String? = null,
            contentType: String? = null,
            algorithm: String? = null,
            jwkSetUrl: String? = null,
            jwk: JWK? = null,
            keyId: String? = null,
            x509CertificateUrl: String? = null,
            x509CertificateChain: List<String>? = null,
            x509CertificateSha1Thumbprint: String? = null,
            x509CertificateSha256Thumbprint: String? = null,
            critical: List<String>? = null,
        ) : this(
            buildMap {
                putAll(entries)
                if (type != null) put("typ", JsonPrimitive(type))
                if (contentType != null) put("cty", JsonPrimitive(contentType))
                if (algorithm != null) put("alg", JsonPrimitive(algorithm))
                if (jwkSetUrl != null) put("jku", JsonPrimitive(jwkSetUrl))
                if (jwk != null) put("jwk", joseJson.encodeToJsonElement<JWK>(jwk))
                if (keyId != null) put("kid", JsonPrimitive(keyId))
                if (x509CertificateUrl != null) put("x5u", JsonPrimitive(x509CertificateUrl))
                if (x509CertificateChain != null) put("x5c", JsonArray(x509CertificateChain.map { JsonPrimitive(it) }))
                if (x509CertificateSha1Thumbprint != null) put("x5t", JsonPrimitive(x509CertificateSha1Thumbprint))
                if (x509CertificateSha256Thumbprint != null)
                    put("x5t#S256", JsonPrimitive(x509CertificateSha256Thumbprint))
                if (critical != null) put("crit", JsonArray(critical.map { JsonPrimitive(it) }))
            }
        )

        val type: String? by lazy { (get("typ") as? JsonPrimitive)?.contentOrNull }
        val contentType: String? by lazy { (get("cty") as? JsonPrimitive)?.contentOrNull }
        val algorithm: String? by lazy { (get("alg") as? JsonPrimitive)?.contentOrNull }
        val jwkSetUrl: String? by lazy { (get("jku") as? JsonPrimitive)?.contentOrNull }
        val jwk: JWK? by lazy { (get("jwk") as? JsonObject)?.let { joseJson.decodeFromJsonElement<JWK>(it) } }
        val keyId: String? by lazy { (get("kid") as? JsonPrimitive)?.contentOrNull }
        val x509CertificateUrl: String? by lazy { (get("x5u") as? JsonPrimitive)?.contentOrNull }
        val x509CertificateChain: List<String>? by lazy { (get("x5c") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } }
        val x509CertificateSha1Thumbprint: String? by lazy { (get("x5t") as? JsonPrimitive)?.contentOrNull }
        val x509CertificateSha256Thumbprint: String? by lazy { (get("x5t#S256") as? JsonPrimitive)?.contentOrNull }
        val critical: List<String>? by lazy { (get("crit") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } }
    }

    override fun toString(): String = "JWS(${encodeToString()})"
}

internal object JWSSerializer : KSerializer<JWS> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("JWSSerializer")

    override fun deserialize(decoder: Decoder): JWS = JWS.decodeFromString(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: JWS) {
        encoder.encodeString(value.encodeToString())
    }
}

internal object JWSHeaderSerializer : JsonDelegateSerializer<JWS.Header>("JWSHeaderSerializer", { JWS.Header(it) })