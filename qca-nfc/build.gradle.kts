import de.connect2x.conventions.withAndroidLibrary
import de.connect2x.conventions.withIos
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSet

plugins {
    alias(sharedLibs.plugins.kotlin.multiplatform)
    alias(sharedLibs.plugins.kotlin.serialization)
    alias(sharedLibs.plugins.android.library)
}

kotlin {
    withAndroidLibrary()
    withIos()

    applyDefaultHierarchyTemplate()

    sourceSets {
        matching(KotlinSourceSet::isNative).configureEach {
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
        }

        commonMain.dependencies {
            api(sharedLibs.ktor.client.core)

            implementation(projects.qcaEncoding)
            implementation(projects.qcaIdp)
            implementation(projects.qcaCrypto)

            implementation(libs.okio)
            implementation(sharedLibs.lognity.api)
            implementation(sharedLibs.kotlinx.coroutines.core)
        }
    }
}


private fun KotlinSourceSet.isNative(): Boolean = when {
    name == "nativeMain" || name == "nativeTest" -> true
    dependsOn.any { it.isNative() } -> true
    else -> false
}

android {
    namespace = "de.connect2x.qca.nfc"
}
