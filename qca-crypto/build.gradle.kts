@file:OptIn(ExperimentalKotlinGradlePluginApi::class)

import de.connect2x.conventions.withIos
import de.connect2x.conventions.withJvm
import de.undercouch.gradle.tasks.download.Download
import org.gradle.kotlin.dsl.sourceSets
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSet
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.KonanTarget

plugins {
    alias(sharedLibs.plugins.kotlin.multiplatform)
    alias(libs.plugins.download)
}

kotlin {
    withJvm()
    withIos()

    applyDefaultHierarchyTemplate {
        common {
            group("openssl") {
                withNative()
            }
        }
    }

    configureOpenssl(
        version = libs.versions.trixnityOpensslBinaries.get(),
    )

    sourceSets {
        matching(KotlinSourceSet::needsExperimentalForeignApi).configureEach {
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
        }

        jvmMain.dependencies {
            api(libs.bundles.bouncycastle)
        }
    }
}

private fun KotlinSourceSet.needsExperimentalForeignApi(): Boolean = when {
    name == "opensslMain" || name == "appleMain" -> true
    dependsOn.any { it.needsExperimentalForeignApi() } -> true
    else -> false
}

private fun KotlinMultiplatformExtension.configureOpenssl(
    version: String,
) {

    val download = tasks.register<Download>("downloadOpensslBinaries") {
        src("https://gitlab.com/api/v4/projects/57407788/packages/generic/build/v$version/build.zip")
        dest(layout.buildDirectory.file("tmp/openssl-binaries-$version.zip"))
        overwrite(false)
    }

    val extract = tasks.register<Copy>("extractOpensslBinaries") {
        from(zipTree(download.map { it.dest })) {
            include("build/**")
            eachFile {
                relativePath = RelativePath(
                    true, *relativePath.segments.drop(1).toTypedArray()
                )
            }
        }
        into(layout.buildDirectory.dir("openssl-binaries/$version"))
    }

    val binaries = extract.map { it.destinationDir }

    fun include(target: KonanTarget) = binaries.map { it.resolve("openssl/${target.name}/include") }

    fun lib(target: KonanTarget) =
        binaries.map { it.resolve("openssl/${target.name}/lib/libcrypto.a") }

    targets.withType<KotlinNativeTarget> {
        val target = konanTarget

        compilations.named { it == "main" }.configureEach {
            cinterops.register("libopenssl") {
                defFile("src/opensslMain/cinterop/libopenssl.def")
                packageName("org.openssl")

                val includeDir = include(target)

                includeDirs.allHeaders(includeDir)

                // This is necessary as allHeaders does not properly set up the task dependency ...
                tasks.named { it == interopProcessingTaskName }.configureEach {
                    inputs.dir(includeDir)
                }
            }

            compileTaskProvider.configure {
                compilerOptions.freeCompilerArgs.add(
                    lib(target).map { "-include-binary=${it.canonicalPath}" })
            }
        }
    }
}
