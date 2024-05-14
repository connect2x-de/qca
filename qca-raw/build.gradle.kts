plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlinx.serialization)
}

@OptIn(org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvm()

    sourceSets {
        commonMain {
            dependencies {
                implementation(project(":qca-crypto"))
                implementation(project(":qca-idp"))
                implementation(libs.oshai.logging)

                api(libs.ktor.client.core)
            }
        }
        jvmMain {
            dependencies {
                implementation(libs.bundles.bouncycastle)
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.kotest.assertions.core)
                implementation(libs.kotlinx.coroutines.test)
            }
        }
    }
}