package de.connect2x.qca.idp.jose

import kotlinx.serialization.json.Json

internal val joseJson by lazy {
    Json {
        ignoreUnknownKeys = true
    }
}