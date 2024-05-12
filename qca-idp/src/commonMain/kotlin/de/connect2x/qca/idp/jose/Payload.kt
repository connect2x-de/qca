package de.connect2x.qca.idp.jose

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull

@Serializable(with = PayloadSerializer::class)
class Payload(delegate: Map<String, JsonElement>) : Map<String, JsonElement> by delegate {
    constructor(
        vararg entries: Pair<String, JsonElement>,
        issuer: String? = null,
        subject: String? = null,
        expirationTime: Long? = null,
        notBefore: Long? = null,
        issuedAt: Long? = null,
        jwtId: String? = null,
    ) : this(
        buildMap {
            putAll(entries)
            if (issuer != null) put("iss", JsonPrimitive(issuer))
            if (subject != null) put("sub", JsonPrimitive(subject))
            if (expirationTime != null) put("exp", JsonPrimitive(expirationTime))
            if (notBefore != null) put("nbf", JsonPrimitive(notBefore))
            if (issuedAt != null) put("iat", JsonPrimitive(issuedAt))
            if (jwtId != null) put("jti", JsonPrimitive(jwtId))
        }
    )

    val issuer: String?
        get() = (get("iss") as? JsonPrimitive)?.contentOrNull
    val subject: String?
        get() = (get("sub") as? JsonPrimitive)?.contentOrNull
    val audience: String?
        get() = (get("aud") as? JsonPrimitive)?.contentOrNull
    val expirationTime: Long?
        get() = (get("exp") as? JsonPrimitive)?.longOrNull
    val notBefore: Long?
        get() = (get("nbf") as? JsonPrimitive)?.longOrNull
    val issuedAt: Long?
        get() = (get("iat") as? JsonPrimitive)?.longOrNull
    val jwtId: String?
        get() = (get("jti") as? JsonPrimitive)?.contentOrNull
}

internal object PayloadSerializer : JsonDelegateSerializer<Payload>("PayloadSerializer", { Payload(it) })