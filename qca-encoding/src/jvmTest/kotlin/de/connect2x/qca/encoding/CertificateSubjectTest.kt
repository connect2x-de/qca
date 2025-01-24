package de.connect2x.qca.encoding

import kotlin.test.Test
import kotlin.test.assertEquals

class CertificateSubjectTest {
    @Test
    fun testHba() {
        val data = CertificateSubject::class.java.getResourceAsStream("/HBA.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "Dr. Hermine Aubertinó TEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testHbaAltenpfleger() {
        val data = CertificateSubject::class.java.getResourceAsStream("/HBA Altenpfleger.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "Altenpfleger Aaron Aal TEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testHbaUnknownIssuer() {
        val data = CertificateSubject::class.java.getResourceAsStream("/HBA unknown-issuer.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "Arzt Uwe Unknown TEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testHbaZahnarzt() {
        val data = CertificateSubject::class.java.getResourceAsStream("/HBA Zahnarzt.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "Gustav SzczyrbelTEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testSmcbApotheke() {
        val data = CertificateSubject::class.java.getResourceAsStream("/SMC-B Apotheke.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "Nord ApothekeTEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testSmcbApothekeAmSportzentrum() {
        val data = CertificateSubject::class.java.getResourceAsStream("/SMC-B Apotheke am Sportzentrum.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "Apotheke am SportzentrumTEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testSmcbExpired() {
        val data = CertificateSubject::class.java.getResourceAsStream("/SMC-B expired.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "fehlerhafte Apotheke TEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testSmcbRevoked() {
        val data = CertificateSubject::class.java.getResourceAsStream("/SMC-B revoked.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "fehlerhafte Apotheke TEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }

    @Test
    fun testSmcbUniversitaetsklinik() {
        val data = CertificateSubject::class.java.getResourceAsStream("/SMC-B Universitätsklinik.der")!!.readAllBytes()
        println(CertificateSubject.fromCertificate(data))
        assertEquals(
            "Universitätsklinik MitteTEST-ONLY",
            CertificateSubject.fromCertificate(data)[CertificateSubject.Attribute.COMMON_NAME],
        )
    }
}
