import de.connect2x.conventions.withJvm

plugins {
    alias(sharedLibs.plugins.kotlin.multiplatform)
    alias(sharedLibs.plugins.kotlin.serialization)
}

kotlin {
    withJvm()

    sourceSets {
        commonMain.dependencies {
            api(projects.qcaIdp)
            api(sharedLibs.ktor.client.core)

            implementation(projects.qcaCrypto)
            implementation(sharedLibs.lognity.api)
        }
        jvmMain.dependencies {
            implementation(libs.bundles.bouncycastle)
        }
    }
}
