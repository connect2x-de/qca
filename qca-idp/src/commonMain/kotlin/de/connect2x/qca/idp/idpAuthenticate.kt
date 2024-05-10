package de.connect2x.qca.idp

import de.connect2x.qca.crypto.BrainpoolP256r1Key
import de.connect2x.qca.crypto.decodeX962
import de.connect2x.qca.crypto.encodeX962
import de.connect2x.qca.crypto.encryptAes256Gcm
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
import io.ktor.utils.io.core.*
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString

/**
 * Authentication flow against an IDP using the [challengeUrl] of a Relying Party and returning the redirect from the IDP.
 */
suspend fun idpAuthenticate(
    challengeUrl: String,
    idpUrl: String,
    signingPublicKey: ByteArray,
    signChallenge: SignChallenge,
    engine: HttpClientEngine? = null,
): String = coroutineScope {
    val config: HttpClientConfig<*>.() -> Unit = {
        expectSuccess = true
        followRedirects = false
        install(ContentNegotiation) {
            json(
                Json {
                    ignoreUnknownKeys = true
                }
            )
        }
    }

    val httpClient = if (engine != null) HttpClient(engine, config) else HttpClient(config)

    val oidcWellKnown =
        httpClient.get("/.well-known/openid-configuration") {
            url.takeFrom(idpUrl)
        }.bodyAsText()
            .let(JWS::decodeFromString) // TODO verify signature?
            .let(OidcWellKnown::fromJWS)

    val peerPublicKey = async {
        val jwk = httpClient.get(oidcWellKnown.pukIdpEncUri).body<JWK>()
        val x = checkNotNull(
            (jwk["x"] as? JsonPrimitive)?.contentOrNull?.decodeBase64()?.toByteArray()
        ) { "x missing in puk_idp_enc" }
        val y =
            checkNotNull(
                (jwk["y"] as? JsonPrimitive)?.contentOrNull?.decodeBase64()?.toByteArray()
            ) { "y missing in puk_idp_enc" }

        encodeX962(x, y)
    }
    val challenge = httpClient.get(challengeUrl).body<Challenge>()

    val signedChallengeToken = JWS.sign(
        header = JWS.Header(
            contentType = "NJWT",
            algorithm = "BP256R1",
            x509CertificateChain = listOf(signingPublicKey.toByteString().base64())
        ),
        payload = Payload(
            "njwt" to JsonPrimitive(challenge.token.encodeToString())
        )
    ) {
        signChallenge(it.toByteArray(), challenge.userConsent)
    }.encodeToString()

    val ephemeralKey = BrainpoolP256r1Key()
    val ephemeralPublicKey = ephemeralKey.publicKey.decodeX962()

    val encryptedSignedChallengeToken = JWE.encrypt(
        header = JWE.Header(
            "exp" to JsonPrimitive(challenge.token.claims.expirationTime),
            "epk" to joseJson.encodeToJsonElement(
                JWK(
                    mapOf(
                        "kty" to JsonPrimitive("EC"),
                        "crv" to JsonPrimitive("BP-256"),
                        "x" to JsonPrimitive(ephemeralPublicKey.x.toByteString().base64Url()),
                        "y" to JsonPrimitive(ephemeralPublicKey.y.toByteString().base64Url())
                    )
                )
            ),
            contentType = "NJWT",
            algorithm = "ECDH-ES",
            encryptionAlgorithm = "A256GCM",
        ),
        payload = Payload(
            "njwt" to JsonPrimitive(signedChallengeToken)
        )
    ) { encryptInputData ->
        val encryptAesGcmResult = encryptInputData.plaintext.encryptAes256Gcm(
            key = ephemeralKey.sharedSecret(peerPublicKey.await()),
            authenticationData = encryptInputData.authenticationData,
        )
        JWE.Companion.EncryptOutputData(
            encryptedKey = ByteArray(0), // not used
            initializationVector = encryptAesGcmResult.initialisationVector,
            ciphertext = encryptAesGcmResult.ciphertext,
            authenticationTag = encryptAesGcmResult.authenticationTag,
        )
    }
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
        fun fromJWS(jws: JWS): OidcWellKnown = Json.decodeFromJsonElement(JsonObject(jws.payload))
    }
}

@Serializable
internal data class Challenge(
    @SerialName("challenge") val token: JWT,
    @SerialName("user_consent") val userConsent: UserConsent,
)

@Serializable
data class UserConsent(
    @SerialName("requested_claims") val requestedClaims: Map<String, String>,
    @SerialName("requested_scopes") val requestedScopes: Map<String, String>,
)