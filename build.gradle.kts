import de.connect2x.conventions.defaultDependencyLocking
import com.vanniktech.maven.publish.MavenPublishPlugin
import de.connect2x.conventions.c2xOrganization
import de.connect2x.conventions.configureJava
import de.connect2x.conventions.defaultCompilerOptions
import de.connect2x.conventions.defaultPublishing
import de.connect2x.conventions.setProjectInfo
import de.connect2x.conventions.withVersionSuffix
import org.jetbrains.dokka.gradle.DokkaPlugin
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

plugins {
    alias(sharedLibs.plugins.c2xConventions)

    alias(sharedLibs.plugins.kotlin.multiplatform) apply false
    alias(sharedLibs.plugins.kotlin.serialization) apply false
    alias(sharedLibs.plugins.android.library) apply false

    alias(sharedLibs.plugins.mavenPublish) apply false
    alias(sharedLibs.plugins.dokka) apply false
}

allprojects {
    group = "de.connect2x.qca"
    version = withVersionSuffix(rootProject.libs.versions.qca)

    if (withLock) defaultDependencyLocking()

    configureJava(rootProject.sharedLibs.versions.targetJvm)

    pluginManager.withPlugin("org.jetbrains.kotlin.multiplatform") {
        extensions.configure<KotlinMultiplatformExtension> {
            defaultCompilerOptions()

            sourceSets {
                commonTest.dependencies {
                    implementation(sharedLibs.kotlin.test)
                    implementation(sharedLibs.kotest.assertions.core)
                    implementation(sharedLibs.kotlinx.coroutines.test)
                    implementation(sharedLibs.lognity.test)
                }
            }
        }
    }
}

subprojects {
    if (!name.startsWith("qca-")) return@subprojects

    apply<MavenPublishPlugin>()
    apply<DokkaPlugin>()

    defaultPublishing()

    extensions.configure<PublishingExtension> {
        publications.withType<MavenPublication>().configureEach {
            pom {
                agpl3()
                c2xOrganization()
                setProjectInfo(
                    name = project.name,
                    description = "Multiplatform Kotlin SDK for Gematik IDP authentication using health care cards",
                    repository = "connect2x/qca",
                )
            }
        }
    }
}

private inline val Project.withLock: Boolean
    get() = providers.environmentVariable("WITH_LOCK")
        .map(String::toBoolean)
        .getOrElse(false)

private fun MavenPom.agpl3() {
    licenses {
        license {
            name.set("GNU Affero General Public License v3.0 only")
            url.set("https://www.gnu.org/licenses/agpl-3.0.html")
        }
    }
}
