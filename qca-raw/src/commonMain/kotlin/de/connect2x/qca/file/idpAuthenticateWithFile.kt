package de.connect2x.qca.file

import de.connect2x.qca.idp.idpAuthenticate
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
    engine: HttpClientEngine? = null,
): String =
    idpAuthenticate(
        challengeUrl = challengeUrl,
        idpUrl = idpUrl,
        signingPublicKey = signingPublicKey,
        signChallenge = SignChallengeWithPrivateKey(signingPrivateKey),
        engine = engine
    )