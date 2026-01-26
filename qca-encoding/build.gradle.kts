import de.connect2x.conventions.withIos
import de.connect2x.conventions.withJvm

plugins {
    alias(sharedLibs.plugins.kotlin.multiplatform)
}

kotlin {
    withJvm()
    withIos()

    sourceSets {
        commonMain.dependencies {
            api(libs.signum)
            api(libs.bignum)
        }
        jvmMain.dependencies {
            api(libs.bundles.bouncycastle)
        }
    }
}
