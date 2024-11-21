package de.connect2x.qca.nfc

import de.connect2x.qca.idp.idpAuthenticate
import de.connect2x.qca.nfc.card.*
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.*
import io.ktor.client.engine.*

private val log = KotlinLogging.logger { }

/**
 * Allows to authenticate against the gematik IDP with NFC
 */
suspend fun idpAuthenticateWithNfc(
    challengeUrl: String,
    idpUrl: String,
    can: String,
    pin: String,
    nfcCardFactory: NfcCardFactory,
    httpClientEngine: HttpClientEngine? = null,
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
): String =
    useNfcCardSecured(nfcCardFactory = nfcCardFactory, can = can) {
        val cardInfo = retrieveCardInfo()
        val signingPublicKey = retrieveSigningCertificate(cardInfo)
        verifyPin(pin, cardInfo)
        idpAuthenticate(
            challengeUrl = challengeUrl,
            idpUrl = idpUrl,
            signingPublicKey = signingPublicKey,
            signChallenge = { challenge, _ ->
                signChallenge(challenge, cardInfo)
            },
            httpClientEngine = httpClientEngine,
            httpClientConfig = httpClientConfig,
        )
    }
