package de.connect2x.qca.idp.jose

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.encodeUtf8

@Serializable(with = JWTSerializer::class)
class JWT(
    val header: Header,
    val claims: Payload,
) {
    companion object {
        fun decodeFromString(encoded: String): JWT {
            val components =
                encoded.split(".").map { checkNotNull(it.decodeBase64()) { "could not decode base64 in JWT" } }
            check(components.size == 2) { "JWT did not contain exactly two parts" }

            return JWT(
                header = joseJson.decodeFromString(components[0].utf8()),
                claims = joseJson.decodeFromString(components[1].utf8()),
            )
        }
    }

    fun encodeToString(): String =
        listOf(
            joseJson.encodeToString(header).encodeUtf8().base64UrlUnpadded(),
            joseJson.encodeToString(claims).encodeUtf8().base64UrlUnpadded(),
        ).joinToString(".")

    @Serializable(with = JWTHeaderSerializer::class)
    class Header(delegate: Map<String, JsonElement>) : Map<String, JsonElement> by delegate {
        constructor(
            vararg entries: Pair<String, JsonElement>,
            type: String? = null,
            contentType: String? = null,
        ) : this(
            buildMap {
                putAll(entries)
                if (type != null) put("typ", JsonPrimitive(type))
                if (contentType != null) put("cty", JsonPrimitive(contentType))
            }
        )

        val type: String?
            get() = (get("typ") as? JsonPrimitive)?.contentOrNull
        val contentType: String?
            get() = (get("cty") as? JsonPrimitive)?.contentOrNull
    }

    override fun toString(): String = "JWT(${encodeToString()})"
}

internal object JWTSerializer : KSerializer<JWT> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("JWTSerializer")

    override fun deserialize(decoder: Decoder): JWT = JWT.decodeFromString(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: JWT) {
        encoder.encodeString(value.encodeToString())
    }
}

internal object JWTHeaderSerializer : JsonDelegateSerializer<JWT.Header>("JWTHeaderSerializer", { JWT.Header(it) })
