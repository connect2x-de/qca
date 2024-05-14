# QCA - Quality Card Authenticator

Multiplatform Kotlin SDK for gematik idp authentication using health care cards

## Upgrade lock

If any dependency is upgraded, the locks also have to be upgraded. This is done with the following command:

Run `./gradlew dependenciesForAll --write-locks --no-parallel`.