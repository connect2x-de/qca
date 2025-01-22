rootProject.name = "qca"
include(":qca-crypto", ":qca-encoding", ":qca-idp", ":qca-raw", ":qca-nfc")

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

buildCache {
    local {
        directory = File(rootDir, ".gradle").resolve("build-cache")
        removeUnusedEntriesAfterDays = 30
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version ("0.8.0") // https://github.com/gradle/foojay-toolchains/tags
}