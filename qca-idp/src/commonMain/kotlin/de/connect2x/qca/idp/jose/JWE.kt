package de.connect2x.qca.idp.jose

import de.connect2x.qca.crypto.BrainpoolP256r1Key
import de.connect2x.qca.crypto.SecureRandom
import de.connect2x.qca.crypto.decodeX962
import de.connect2x.qca.crypto.encryptAes256Gcm
import de.connect2x.qca.idp.jose.JWE.Header
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString

@Serializable(with = JWESerializer::class)
class JWE(
    val header: Header,
    val encryptedKey: ByteArray,
    val initializationVector: ByteArray,
    val ciphertext: ByteArray,
    val authenticationTag: ByteArray,
) {
    companion object {
        fun decodeFromString(encoded: String): JWE {
            val components =
                encoded.split(".").map { checkNotNull(it.decodeBase64()) { "could not decode base64 in JWE" } }
            check(components.size == 5) { "JWE did not contain exactly five parts" }

            return JWE(
                header = joseJson.decodeFromString(components[0].utf8()),
                encryptedKey = components[1].toByteArray(),
                initializationVector = components[2].toByteArray(),
                ciphertext = components[3].toByteArray(),
                authenticationTag = components[4].toByteArray(),
            )
        }

        data class EncryptInputData(
            val plaintext: ByteArray,
            val authenticationData: ByteArray,
        )

        data class EncryptOutputData(
            val encryptedKey: ByteArray,
            val initializationVector: ByteArray,
            val ciphertext: ByteArray,
            val authenticationTag: ByteArray,
        )

        fun encrypt(
            header: Header,
            payload: Payload,
            encrypt: (encryptInputData: EncryptInputData) -> EncryptOutputData
        ): JWE {
            val encryptInputData =
                EncryptInputData(
                    plaintext = joseJson.encodeToString(payload).encodeToByteArray(),
                    authenticationData = joseJson.encodeToString(header).encodeUtf8().base64UrlUnpadded()
                        .encodeToByteArray()
                )
            val encryptOutputData = encrypt(encryptInputData)
            return JWE(
                header = header,
                encryptedKey = encryptOutputData.encryptedKey,
                initializationVector = encryptOutputData.initializationVector,
                ciphertext = encryptOutputData.ciphertext,
                authenticationTag = encryptOutputData.authenticationTag
            )
        }
    }

    fun encodeToString(): String =
        listOf(
            joseJson.encodeToString(header).encodeUtf8().base64UrlUnpadded(),
            encryptedKey.toByteString().base64UrlUnpadded(),
            initializationVector.toByteString().base64UrlUnpadded(),
            ciphertext.toByteString().base64UrlUnpadded(),
            authenticationTag.toByteString().base64UrlUnpadded()
        ).joinToString(".")

    @Serializable(with = JWEHeaderSerializer::class)
    class Header(delegate: Map<String, JsonElement>) : Map<String, JsonElement> by delegate {
        constructor(
            vararg entries: Pair<String, JsonElement>,
            type: String? = null,
            contentType: String? = null,
            algorithm: String? = null,
            encryptionAlgorithm: String? = null,
            compressionAlgorithm: String? = null,
            jwkSetUrl: String? = null,
            jwk: JWK? = null,
            keyId: String? = null,
            x509CertificateUrl: String? = null,
            x509CertificateChain: List<String>? = null,
            x509CertificateSha1Thumbprint: String? = null,
            x509CertificateSha256Thumbprint: String? = null,
            critical: List<String>? = null,
        ) : this(
            buildMap {
                putAll(entries)
                if (type != null) put("typ", JsonPrimitive(type))
                if (contentType != null) put("cty", JsonPrimitive(contentType))
                if (algorithm != null) put("alg", JsonPrimitive(algorithm))
                if (encryptionAlgorithm != null) put("enc", JsonPrimitive(encryptionAlgorithm))
                if (compressionAlgorithm != null) put("zip", JsonPrimitive(compressionAlgorithm))
                if (jwkSetUrl != null) put("jku", JsonPrimitive(jwkSetUrl))
                if (jwk != null) put("jwk", joseJson.encodeToJsonElement<JWK>(jwk))
                if (keyId != null) put("kid", JsonPrimitive(keyId))
                if (x509CertificateUrl != null) put("x5u", JsonPrimitive(x509CertificateUrl))
                if (x509CertificateChain != null) put("x5c", JsonArray(x509CertificateChain.map { JsonPrimitive(it) }))
                if (x509CertificateSha1Thumbprint != null) put("x5t", JsonPrimitive(x509CertificateSha1Thumbprint))
                if (x509CertificateSha256Thumbprint != null)
                    put("x5t#S256", JsonPrimitive(x509CertificateSha256Thumbprint))
                if (critical != null) put("crit", JsonArray(critical.map { JsonPrimitive(it) }))
            }
        )

        val type: String? by lazy { (get("typ") as? JsonPrimitive)?.contentOrNull }
        val contentType: String? by lazy { (get("cty") as? JsonPrimitive)?.contentOrNull }
        val algorithm: String? by lazy { (get("alg") as? JsonPrimitive)?.contentOrNull }
        val encryptionAlgorithm: String? by lazy { (get("enc") as? JsonPrimitive)?.contentOrNull }
        val compressionAlgorithm: String? by lazy { (get("zip") as? JsonPrimitive)?.contentOrNull }
        val jwkSetUrl: String? by lazy { (get("jku") as? JsonPrimitive)?.contentOrNull }
        val jwk: JWK? by lazy { (get("jwk") as? JsonObject)?.let { joseJson.decodeFromJsonElement<JWK>(it) } }
        val keyId: String? by lazy { (get("kid") as? JsonPrimitive)?.contentOrNull }
        val x509CertificateUrl: String? by lazy { (get("x5u") as? JsonPrimitive)?.contentOrNull }
        val x509CertificateChain: List<String>? by lazy { (get("x5c") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } }
        val x509CertificateSha1Thumbprint: String? by lazy { (get("x5t") as? JsonPrimitive)?.contentOrNull }
        val x509CertificateSha256Thumbprint: String? by lazy { (get("x5t#S256") as? JsonPrimitive)?.contentOrNull }
        val critical: List<String>? by lazy { (get("crit") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } }
    }

    override fun toString(): String = "JWE(${encodeToString()})"
}

internal object JWESerializer : KSerializer<JWE> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("JWESerializer")

    override fun deserialize(decoder: Decoder): JWE = JWE.decodeFromString(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: JWE) {
        encoder.encodeString(value.encodeToString())
    }
}

internal object JWEHeaderSerializer : JsonDelegateSerializer<JWE.Header>("JWEHeaderSerializer", { JWE.Header(it) })

internal fun JWE.Companion.encryptForIdp(
    header: Header,
    payload: Payload,
    peerPublicKey: ByteArray,
    ephemeralKey: BrainpoolP256r1Key = BrainpoolP256r1Key(),
    initializationVector: ByteArray = SecureRandom.nextBytes(12),
): JWE {
    val ephemeralPublicKey = ephemeralKey.publicKey.decodeX962()
    return encrypt(
        header = Header(
            *header.entries.map { it.toPair() }.toTypedArray(),
            "epk" to joseJson.encodeToJsonElement(
                JWK(
                    "crv" to JsonPrimitive("BP-256"),
                    "x" to JsonPrimitive(ephemeralPublicKey.x.toByteString().base64UrlUnpadded()),
                    "y" to JsonPrimitive(ephemeralPublicKey.y.toByteString().base64UrlUnpadded()),
                    keyType = "EC"
                )
            ),
            algorithm = "ECDH-ES",
            encryptionAlgorithm = "A256GCM",
        ),
        payload = payload,
    ) { encryptInputData ->
        val ciphertext = encryptInputData.plaintext.encryptAes256Gcm(
            key = deriveJWEKey(peerPublicKey, ephemeralKey),
            initializationVector = initializationVector,
            authenticationData = encryptInputData.authenticationData,
        )
        JWE.Companion.EncryptOutputData(
            encryptedKey = ByteArray(0), // not used
            initializationVector = initializationVector,
            ciphertext = ciphertext.copyOfRange(0, ciphertext.size - 16),
            authenticationTag = ciphertext.copyOfRange(ciphertext.size - 16, ciphertext.size),
        )
    }
}

@OptIn(ExperimentalStdlibApi::class)
internal fun deriveJWEKey(
    peerPublicKey: ByteArray,
    ephemeralKey: BrainpoolP256r1Key = BrainpoolP256r1Key()
): ByteArray {
    val sharedSecret = ephemeralKey.sharedSecret(peerPublicKey)

    // Magic KDF
    // https://tools.ietf.org/html/rfc5084
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
    val part1 = "00000001".hexToByteArray()
    val part2 = "000000074132353647434d000000000000000000000100".hexToByteArray() // contains "A256GCM"
    return (part1 + sharedSecret + part2).toByteString().sha256().toByteArray()
}