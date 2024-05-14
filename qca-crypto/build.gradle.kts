import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.KonanTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.download)
}

class TrixnityOpensslBinariesDirs(project: Project) {
    val root = project.rootProject.layout.buildDirectory.get().asFile
        .resolve("trixnity-openssl-binaries").resolve(libs.versions.trixnityOpensslBinaries.get())

    private val rootDir = root.resolve("openssl")
    private fun targetDir(target: KonanTarget) = rootDir.resolve(target.name)
    fun include(target: KonanTarget) = targetDir(target).resolve("include")
    fun lib(target: KonanTarget) = targetDir(target).resolve("lib").resolve("libcrypto.a")
}

val trixnityOlmBinariesDirs = TrixnityOpensslBinariesDirs(project)

@OptIn(org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi::class)
kotlin {
    val kotlinJvm = libs.versions.kotlinJvmTarget.get()
    jvmToolchain(kotlinJvm.toInt())
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = kotlinJvm
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    iosArm64()
    iosSimulatorArm64()
    iosX64()

    targets.withType<KotlinNativeTarget> {
        compilations {
            "main" {
                cinterops {
                    create("libopenssl") {
                        defFile(project.file("src/opensslMain/cinterop/libopenssl.def"))
                        packageName("org.openssl")
                        includeDirs.allHeaders(trixnityOlmBinariesDirs.include(target.konanTarget).absolutePath)
                        tasks.named(interopProcessingTaskName) {
                            dependsOn(trixnityBinaries)
                        }
                    }
                }

                kotlinOptions.freeCompilerArgs =
                    listOf("-include-binary", trixnityOlmBinariesDirs.lib(target.konanTarget).absolutePath)
            }
        }
    }
    applyDefaultHierarchyTemplate()

    sourceSets {
        all {
            languageSettings.optIn("kotlin.RequiresOptIn")
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
        }
        commonMain {
            dependencies {
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.kotest.assertions.core)
                implementation(libs.kotlinx.coroutines.test)
            }
        }
        jvmMain {
            dependencies {
                implementation(libs.bundles.bouncycastle)
            }
        }
        val opensslMain by creating {
            dependsOn(nativeMain.get())
        }
        appleMain.get().dependsOn(opensslMain)
    }
}

val tmpDir = layout.buildDirectory.get().asFile.resolve("tmp")
val opensslBinariesZipDir =
    tmpDir.resolve("trixnity-openssl-binaries-${libs.versions.trixnityOpensslBinaries.get()}.zip")

val downloadOpensslBinaries by tasks.registering(de.undercouch.gradle.tasks.download.Download::class) {
    src("https://gitlab.com/api/v4/projects/57407788/packages/generic/build/v${libs.versions.trixnityOpensslBinaries.get()}/build.zip")
    dest(opensslBinariesZipDir)
    overwrite(false)
}

val extractOpensslBinaries by tasks.registering(Copy::class) {
    from(zipTree(opensslBinariesZipDir)) {
        include("build/**")
        eachFile {
            relativePath = RelativePath(true, *relativePath.segments.drop(1).toTypedArray())
        }
    }
    into(trixnityOlmBinariesDirs.root)
    outputs.cacheIf { true }
    inputs.files(downloadOpensslBinaries)
    dependsOn(downloadOpensslBinaries)
}

val trixnityBinaries by tasks.registering {
    dependsOn(extractOpensslBinaries)
}