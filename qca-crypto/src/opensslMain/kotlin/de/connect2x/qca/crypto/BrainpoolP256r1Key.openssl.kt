@file:OptIn(ExperimentalForeignApi::class)

package de.connect2x.qca.crypto

import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import org.openssl.*


actual class BrainpoolP256r1Key {
    actual val privateKey: ByteArray
    actual val publicKey: ByteArray

    actual constructor() {
        val ecGroup = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1)
        try {
            privateKey = SecureRandom.nextBytes((EC_GROUP_get_degree(ecGroup) + 7) / 8)
            publicKey = publicKeyFromPrivateKey(privateKey)
        } finally {
            EC_GROUP_free(ecGroup)
        }
    }

    actual constructor(privateKey: ByteArray) {
        this.privateKey = privateKey
        publicKey = publicKeyFromPrivateKey(privateKey)
    }

    actual constructor(privateKey: ByteArray, publicKey: ByteArray) {
        this.privateKey = privateKey
        this.publicKey = publicKey
    }

    private fun publicKeyFromPrivateKey(privateKey: ByteArray): ByteArray = withFree {
        val ecGroup = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1).checkNotNullError().freeAfter(::EC_GROUP_free)
        val ecPoint = EC_POINT_new(ecGroup).checkNotNullError().freeAfter(::EC_POINT_free)
        val privateKeyBigNum = convertToBigNum(privateKey)
        EC_POINT_mul(ecGroup, ecPoint, privateKeyBigNum, null, null, null).checkError()
        convertToECPoint(ecPoint, ecGroup).encodeX962()
    }

    /**
     * Compute a shared secret using the given public key.
     * @param peerPublicKey: the public key material to derive a shared secret in conjunction with its own private information.
     * @return The shared secret in raw bytes
     */
    actual fun sharedSecret(peerPublicKey: ByteArray): ByteArray = withFree {
        val ecGroup = EC_GROUP_new_by_curve_name(NID_brainpoolP256r1).checkNotNullError().freeAfter(::EC_GROUP_free)
        val ecPoint = convertToOpensslECPoint(peerPublicKey.decodeX962(), ecGroup)
        val privateKeyBigNum = convertToBigNum(privateKey)
        val sharedSecretECPoint = EC_POINT_new(ecGroup).checkNotNullError().freeAfter(::EC_POINT_free)
        EC_POINT_mul(ecGroup, sharedSecretECPoint, null, ecPoint, privateKeyBigNum, null).checkError()
        convertToECPoint(sharedSecretECPoint, ecGroup).x
            .dropLeadingZeroByte()
    }

    private fun WithFree.convertToOpensslECPoint(
        ecPoint: ECPoint,
        ecGroup: CValuesRef<EC_GROUP>,
    ): CValuesRef<EC_POINT> {
        val opensslEcPoint = EC_POINT_new(ecGroup).checkNotNullError().freeAfter(::EC_POINT_free)
        EC_POINT_set_affine_coordinates(
            group = ecGroup,
            p = opensslEcPoint,
            x = convertToBigNum(ecPoint.x),
            y = convertToBigNum(ecPoint.y),
            ctx = null,
        ).checkError()
        return opensslEcPoint
    }

    private fun WithFree.convertToECPoint(
        opensslECPoint: CValuesRef<EC_POINT>,
        ecGroup: CValuesRef<EC_GROUP>,
    ): ECPoint {
        val x = BN_new().checkNotNullError().freeAfter(::BN_free)
        val y = BN_new().checkNotNullError().freeAfter(::BN_free)
        EC_POINT_get_affine_coordinates(
            group = ecGroup,
            p = opensslECPoint,
            x = x,
            y = y,
            ctx = null,
        )
        return ECPoint(
            x = convertToByteArray(x),
            y = convertToByteArray(y),
        )
    }

    private fun WithFree.convertToBigNum(value: ByteArray): CValuesRef<BIGNUM> =
        value.toUByteArray().usePinned { pinnedValue ->
            BN_bin2bn(
                s = pinnedValue.addressOf(0),
                len = privateKey.size,
                ret = null
            ).checkNotNullError().freeAfter(::BN_free)
        }

    private fun WithFree.convertToByteArray(bigNum: CValuesRef<BIGNUM>): ByteArray {
        val byteArray = ByteArray((BN_num_bits(bigNum) + 7) / 8)
        byteArray.asUByteArray().usePinned { pinnedByteArray ->
            BN_bn2bin(bigNum, pinnedByteArray.addressOf(0)).checkError()
        }
        return byteArray
    }
}