package de.connect2x.qca.idp

import de.connect2x.lognity.api.logger.Logger
import de.connect2x.qca.crypto.ECPointImpl
import de.connect2x.qca.idp.jose.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.core.toByteArray
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString

private val log = Logger("de.connect2x.qca.idp.idpAuthenticate")

/**
 * Authentication flow against an IDP using the [challengeUrl] of a Relying Party and returning the redirect from the IDP.
 *
 * @param signingPublicKey must be ASN.1 DER-Encoding
 */
suspend fun idpAuthenticate(
    challengeUrl: String,
    idpUrl: String,
    signingPublicKey: ByteArray,
    signChallenge: SignChallenge,
    httpClientEngine: HttpClientEngine? = null,
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
): String = coroutineScope {
    val finalHttpClientConfig: HttpClientConfig<*>.() -> Unit = {
        expectSuccess = true
        followRedirects = false
        install(ContentNegotiation) {
            json(
                Json {
                    ignoreUnknownKeys = true
                }
            )
        }

        httpClientConfig?.invoke(this)
    }
    (if (httpClientEngine == null) HttpClient(finalHttpClientConfig)
    else HttpClient(httpClientEngine, finalHttpClientConfig)).use { httpClient ->
        
        val oidcWellKnown =
            httpClient.get {
                url.takeFrom(idpUrl)
                url("/.well-known/openid-configuration")
            }.bodyAsText()
                .let(JWS::decodeFromString) // TODO verify signature?
                .let(OidcWellKnown::fromJWS)

        log.debug { "got config from IDP" }

        val peerPublicKey = async {
            val jwk = httpClient.get(oidcWellKnown.pukIdpEncUri).body<JWK>()
            log.debug { "got enc key from IDP" }
            val x =
                checkNotNull(
                    (jwk["x"] as? JsonPrimitive)?.contentOrNull?.decodeBase64()?.toByteArray()
                ) { "x missing in puk_idp_enc" }
            val y =
                checkNotNull(
                    (jwk["y"] as? JsonPrimitive)?.contentOrNull?.decodeBase64()?.toByteArray()
                ) { "y missing in puk_idp_enc" }

            ECPointImpl(x, y).encodeX962()
        }
        val challenge = httpClient.get(challengeUrl).body<Challenge>()
        log.debug { "got challenge from IDP: $challenge" }

        val signedChallengeToken = JWS.sign(
            header = JWS.Header(
                type = "JWT",
                contentType = "NJWT",
                algorithm = "BP256R1",
                x509CertificateChain = listOf(signingPublicKey.toByteString().base64())
            ),
            payload = Payload(
                "njwt" to JsonPrimitive(challenge.token.encodeToString())
            )
        ) {
            signChallenge(it.toByteArray(), challenge.userConsent)
        }

        log.debug { "signed challenge: $signedChallengeToken" }


        val encryptedSignedChallengeToken =
            JWE.encryptForIdp(
                header = JWE.Header(
                    "exp" to JsonPrimitive(challenge.token.payload.expirationTime),
                    contentType = "NJWT",
                ),
                payload = Payload(
                    "njwt" to JsonPrimitive(signedChallengeToken.encodeToString())
                ),
                peerPublicKey = peerPublicKey.await(),
            )
        log.debug { "encrypted challenge: $encryptedSignedChallengeToken" }
        try {
            httpClient.submitForm(
                url = oidcWellKnown.authorizationEndpoint,
                formParameters = parameters {
                    append("signed_challenge", encryptedSignedChallengeToken.encodeToString())
                }
            )
            throw IllegalStateException("got no redirect")
        } catch (redirect: RedirectResponseException) {
            checkNotNull(redirect.response.headers[HttpHeaders.Location]) { "redirect url was null" }
        }
    }
}

fun interface SignChallenge {
    suspend operator fun invoke(challenge: ByteArray, userConsent: UserConsent): ByteArray
}

@Serializable
internal data class OidcWellKnown(
    @SerialName("uri_puk_idp_enc") val pukIdpEncUri: String,
    @SerialName("uri_puk_idp_sig") val pukIdpSigUri: String,
    @SerialName("authorization_endpoint") val authorizationEndpoint: String,
    @SerialName("token_endpoint") val tokenEndpoint: String
) {
    companion object {
        fun fromJWS(jws: JWS): OidcWellKnown = joseJson.decodeFromJsonElement(JsonObject(jws.payload))
    }
}

@Serializable
internal data class Challenge(
    @SerialName("challenge") val token: JWS,
    @SerialName("user_consent") val userConsent: UserConsent,
)

@Serializable
data class UserConsent(
    @SerialName("requested_claims") val requestedClaims: Map<String, String>,
    @SerialName("requested_scopes") val requestedScopes: Map<String, String>,
)