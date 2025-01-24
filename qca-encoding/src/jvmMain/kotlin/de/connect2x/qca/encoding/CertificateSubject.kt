package de.connect2x.qca.encoding

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.x500.AttributeTypeAndValue
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder

data class CertificateSubject(val entries: List<Map<Attribute, String>>) {
    operator fun get(key: Attribute): String? = entries.firstNotNullOfOrNull { it[key] }

    enum class Attribute(val id: ASN1ObjectIdentifier) {
        OBJECT_CLASS(ASN1ObjectIdentifier("2.5.4.0")),
        ALIASED_ENTRY_NAME(ASN1ObjectIdentifier("2.5.4.1")),
        KNOWLEDGE_INFORMATION(ASN1ObjectIdentifier("2.5.4.2")),
        COMMON_NAME(ASN1ObjectIdentifier("2.5.4.3")),
        SURNAME(ASN1ObjectIdentifier("2.5.4.4")),
        SERIAL_NUMBER(ASN1ObjectIdentifier("2.5.4.5")),
        COUNTRY_NAME(ASN1ObjectIdentifier("2.5.4.6")),
        LOCALITY_NAME(ASN1ObjectIdentifier("2.5.4.7")),
        STATE_OR_PROVINCE_NAME(ASN1ObjectIdentifier("2.5.4.8")),
        STREET_ADDRESS(ASN1ObjectIdentifier("2.5.4.9")),
        ORGANIZATION_NAME(ASN1ObjectIdentifier("2.5.4.10")),
        ORGANIZATIONAL_UNIT_NAME(ASN1ObjectIdentifier("2.5.4.11")),
        TITLE(ASN1ObjectIdentifier("2.5.4.12")),
        DESCRIPTION(ASN1ObjectIdentifier("2.5.4.13")),
        SEARCH_GUIDE(ASN1ObjectIdentifier("2.5.4.14")),
        BUSINESS_CATEGORY(ASN1ObjectIdentifier("2.5.4.15")),
        POSTAL_ADDRESS(ASN1ObjectIdentifier("2.5.4.16")),
        POSTAL_CODE(ASN1ObjectIdentifier("2.5.4.17")),
        POST_OFFICE_BOX(ASN1ObjectIdentifier("2.5.4.18")),
        PHYSICAL_DELIVERY_OFFICE_NAME(ASN1ObjectIdentifier("2.5.4.19")),
        TELEPHONE_NUMBER(ASN1ObjectIdentifier("2.5.4.20")),
        TELEX_NUMBER(ASN1ObjectIdentifier("2.5.4.21")),
        TELETEX_TERMINAL_IDENTIFIER(ASN1ObjectIdentifier("2.5.4.22")),
        FACSIMILE_TELEPHONE_NUMBER(ASN1ObjectIdentifier("2.5.4.23")),
        X121_ADDRESS(ASN1ObjectIdentifier("2.5.4.24")),
        INTERNATIONAL_I_S_D_N_NUMBER(ASN1ObjectIdentifier("2.5.4.25")),
        REGISTERED_ADDRESS(ASN1ObjectIdentifier("2.5.4.26")),
        DESTINATION_INDICATOR(ASN1ObjectIdentifier("2.5.4.27")),
        PREFERRED_DELIVERY_METHOD(ASN1ObjectIdentifier("2.5.4.28")),
        PRESENTATION_ADDRESS(ASN1ObjectIdentifier("2.5.4.29")),
        SUPPORTED_APPLICATION_CONTEXT(ASN1ObjectIdentifier("2.5.4.30")),
        MEMBER(ASN1ObjectIdentifier("2.5.4.31")),
        OWNER(ASN1ObjectIdentifier("2.5.4.32")),
        ROLE_OCCUPANT(ASN1ObjectIdentifier("2.5.4.33")),
        SEE_ALSO(ASN1ObjectIdentifier("2.5.4.34")),
        USER_PASSWORD(ASN1ObjectIdentifier("2.5.4.35")),
        USER_CERTIFICATE(ASN1ObjectIdentifier("2.5.4.36")),
        C_A_CERTIFICATE(ASN1ObjectIdentifier("2.5.4.37")),
        AUTHORITY_REVOCATION_LIST(ASN1ObjectIdentifier("2.5.4.38")),
        CERTIFICATE_REVOCATION_LIST(ASN1ObjectIdentifier("2.5.4.39")),
        CROSS_CERTIFICATE_PAIR(ASN1ObjectIdentifier("2.5.4.40")),
        NAME(ASN1ObjectIdentifier("2.5.4.41")),
        GIVEN_NAME(ASN1ObjectIdentifier("2.5.4.42")),
        INITIALS(ASN1ObjectIdentifier("2.5.4.43")),
        GENERATION_QUALIFIER(ASN1ObjectIdentifier("2.5.4.44")),
        UNIQUE_IDENTIFIER(ASN1ObjectIdentifier("2.5.4.45")),
        DN_QUALIFIER(ASN1ObjectIdentifier("2.5.4.46")),
        ENHANCED_SEARCH_GUIDE(ASN1ObjectIdentifier("2.5.4.47")),
        PROTOCOL_INFORMATION(ASN1ObjectIdentifier("2.5.4.48")),
        DISTINGUISHED_NAME(ASN1ObjectIdentifier("2.5.4.49")),
        UNIQUE_MEMBER(ASN1ObjectIdentifier("2.5.4.50")),
        HOUSE_IDENTIFIER(ASN1ObjectIdentifier("2.5.4.51")),
        SUPPORTED_ALGORITHMS(ASN1ObjectIdentifier("2.5.4.52")),
        DELTA_REVOCATION_LIST(ASN1ObjectIdentifier("2.5.4.53")),
        DMD_NAME(ASN1ObjectIdentifier("2.5.4.54")),
        CLEARANCE(ASN1ObjectIdentifier("2.5.4.55")),
        DEFAULT_DIR_QOP(ASN1ObjectIdentifier("2.5.4.56")),
        ATTRIBUTE_INTEGRITY_INFO(ASN1ObjectIdentifier("2.5.4.57")),
        ATTRIBUTE_CERTIFICATE(ASN1ObjectIdentifier("2.5.4.58")),
        ATTRIBUTE_CERTIFICATE_REVOCATION_LIST(ASN1ObjectIdentifier("2.5.4.59")),
        CONF_KEY_INFO(ASN1ObjectIdentifier("2.5.4.60")),
        A_A_CERTIFICATE(ASN1ObjectIdentifier("2.5.4.61")),
        ATTRIBUTE_DESCRIPTOR_CERTIFICATE(ASN1ObjectIdentifier("2.5.4.62")),
        ATTRIBUTE_AUTHORITY_REVOCATION_LIST(ASN1ObjectIdentifier("2.5.4.63")),
        FAMILY_INFORMATION(ASN1ObjectIdentifier("2.5.4.64")),
        PSEUDONYM(ASN1ObjectIdentifier("2.5.4.65")),
        COMMUNICATIONS_SERVICE(ASN1ObjectIdentifier("2.5.4.66")),
        COMMUNICATIONS_NETWORK(ASN1ObjectIdentifier("2.5.4.67")),
        CERTIFICATION_PRACTICE_STMT(ASN1ObjectIdentifier("2.5.4.68")),
        CERTIFICATE_POLICY(ASN1ObjectIdentifier("2.5.4.69")),
        PKI_PATH(ASN1ObjectIdentifier("2.5.4.70")),
        PRIV_POLICY(ASN1ObjectIdentifier("2.5.4.71")),
        ROLE(ASN1ObjectIdentifier("2.5.4.72")),
        DELEGATION_PATH(ASN1ObjectIdentifier("2.5.4.73")),
        PROT_PRIV_POLICY(ASN1ObjectIdentifier("2.5.4.74")),
        X_M_L_PRIVILEGE_INFO(ASN1ObjectIdentifier("2.5.4.75")),
        XML_PRIV_POLICY(ASN1ObjectIdentifier("2.5.4.76")),
        UUIDPAIR(ASN1ObjectIdentifier("2.5.4.77")),
        TAG_OID(ASN1ObjectIdentifier("2.5.4.78")),
        UII_FORMAT(ASN1ObjectIdentifier("2.5.4.79")),
        UII_IN_URH(ASN1ObjectIdentifier("2.5.4.80")),
        CONTENT_URL(ASN1ObjectIdentifier("2.5.4.81")),
        PERMISSION(ASN1ObjectIdentifier("2.5.4.82")),
        URI(ASN1ObjectIdentifier("2.5.4.83")),
        PWD_ATTRIBUTE(ASN1ObjectIdentifier("2.5.4.84")),
        USER_PWD(ASN1ObjectIdentifier("2.5.4.85")),
        URN(ASN1ObjectIdentifier("2.5.4.86")),
        URL(ASN1ObjectIdentifier("2.5.4.87")),
        UTM_COORDINATES(ASN1ObjectIdentifier("2.5.4.88")),
        URN_C(ASN1ObjectIdentifier("2.5.4.89")),
        UII(ASN1ObjectIdentifier("2.5.4.90")),
        EPC(ASN1ObjectIdentifier("2.5.4.91")),
        TAG_AFI(ASN1ObjectIdentifier("2.5.4.92")),
        EPC_FORMAT(ASN1ObjectIdentifier("2.5.4.93")),
        EPC_IN_URN(ASN1ObjectIdentifier("2.5.4.94")),
        LDAP_URL(ASN1ObjectIdentifier("2.5.4.95")),
        ID_AT_TAG_LOCATION(ASN1ObjectIdentifier("2.5.4.96")),
        ORGANIZATION_IDENTIFIER(ASN1ObjectIdentifier("2.5.4.97")),
        ID_AT_COUNTRY_CODE3C(ASN1ObjectIdentifier("2.5.4.98")),
        ID_AT_COUNTRY_CODE3N(ASN1ObjectIdentifier("2.5.4.99")),
        ID_AT_DNS_NAME(ASN1ObjectIdentifier("2.5.4.100")),
        ID_AT_EEPK_CERTIFICATE_REVOCATION_LIST(ASN1ObjectIdentifier("2.5.4.101")),
        ID_AT_EE_ATTR_CERTIFICATE_REVOCATION_LIST(ASN1ObjectIdentifier("2.5.4.102")),
        ID_AT_SUPPORTED_PUBLIC_KEY_ALGORITHMS(ASN1ObjectIdentifier("2.5.4.103")),
        ID_AT_INT_EMAIL(ASN1ObjectIdentifier("2.5.4.104")),
        ID_AT_JID(ASN1ObjectIdentifier("2.5.4.105")),
        ID_AT_OBJECT_IDENTIFIER(ASN1ObjectIdentifier("2.5.4.106"));

        companion object {
            private val map = entries.associateBy(Attribute::id)

            fun of(value: ASN1ObjectIdentifier): Attribute? = map[value]
        }
    }

    companion object {
        private fun parseAttribute(entry: AttributeTypeAndValue): Pair<Attribute, String>? {
            return Pair(
                Attribute.of(entry.type) ?: return null,
                entry.value.toASN1Primitive().toASN1String()?.string ?: return null,
            )
        }

        fun fromName(name: X500Name): CertificateSubject {
            return CertificateSubject(
                name.rdNs.map { rdn ->
                    rdn.typesAndValues.mapNotNull(::parseAttribute).toMap()
                }
            )
        }

        fun fromCertificate(certificate: X509CertificateHolder): CertificateSubject =
            fromName(certificate.subject)

        fun fromCertificate(data: ByteArray): CertificateSubject =
            fromCertificate(X509CertificateHolder(data))
    }
}

private fun ASN1Primitive.toASN1String() = this as? ASN1String
