package de.connect2x.qca.file

import de.connect2x.qca.idp.idpAuthenticate
import io.ktor.client.*
import io.ktor.client.engine.*

/**
 * Allows to authenticate against the gematik IDP with certificate files
 *
 * @param signingPublicKey must be ASN.1 DER-Encoding (usually a .crt file)
 * @param signingPrivateKey must be PKCS#7 (usually a .prv file)
 */
suspend fun idpAuthenticateWithFile(
    challengeUrl: String,
    idpUrl: String,
    signingPublicKey: ByteArray,
    signingPrivateKey: ByteArray,
    httpClientEngine: HttpClientEngine? = null,
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
): String =
    idpAuthenticate(
        challengeUrl = challengeUrl,
        idpUrl = idpUrl,
        signingPublicKey = signingPublicKey,
        signChallenge = SignChallengeWithPrivateKey(signingPrivateKey),
        httpClientEngine = httpClientEngine,
        httpClientConfig = httpClientConfig,
    )