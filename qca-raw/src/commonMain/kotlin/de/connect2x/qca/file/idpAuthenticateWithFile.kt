package de.connect2x.qca.file

import de.connect2x.qca.idp.idpAuthenticate
import io.ktor.client.engine.*

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