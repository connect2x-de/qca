package de.connect2x.qca.nfc.card

/**
 * eGK 2.1 file system objects
 * @see gemSpec_eGK_ObjSys_G2_1_V4_0_0 'Spezifikation der eGK Objektsystem G2.1'
 */

internal object Ef {
    object CardAccess {
        const val FID = 0x011C
        const val SFID = 0x1C
    }

    object Version2 {
        const val FID = 0x2F11
        const val SFID = 0x11
    }
}

internal object Df {
    object Esign {
        const val AID = "A000000167455349474E"
    }
}

internal object Mf {
    object Df {
        object Esign {
            object Ef {
                // gemSpec_eGK_ObjSys_G2_1#5.5.9
                object CChAutE256 {
                    const val FID = 0xC504
                    const val SFID = 0x04
                }

                object CHpAutE256 {
                    const val FID = 0xC506
                    const val SFID = 0x06
                }

                object CHpAutR2048 {
                    const val FID = 0xC500
                    const val SFID = 0x01
                }
            }

            object PrK {
                object ChAutE256 {
                    const val KID = 0x04
                }

                object HpAutE256 {
                    const val KID = 0x06
                }

                object HpAutR2048 {
                    const val KID = 0x02
                }
            }
        }
    }
}
