import de.connect2x.conventions.withIos
import de.connect2x.conventions.withJvm

plugins {
    alias(sharedLibs.plugins.kotlin.multiplatform)
    alias(sharedLibs.plugins.kotlin.serialization)
}

kotlin {
    withJvm()
    withIos()

    sourceSets {
        commonMain.dependencies {
            api(libs.okio)
            api(sharedLibs.kotlinx.serialization.core)
            api(sharedLibs.kotlinx.serialization.json)
            api(sharedLibs.ktor.client.core)

            implementation(sharedLibs.ktor.http)
            implementation(sharedLibs.ktor.utils)
            implementation(sharedLibs.ktor.client.contentNegotiation)
            implementation(sharedLibs.ktor.serialization.kotlinx.json)

            implementation(projects.qcaCrypto)
            implementation(sharedLibs.lognity.api)
            implementation(sharedLibs.kotlinx.coroutines.core)
        }
    }
}
