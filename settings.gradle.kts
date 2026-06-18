@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories {
        gradlePluginPortal()
        maven("https://gitlab.com/api/v4/projects/68438621/packages/maven") // c2x Conventions
    }
}

dependencyResolutionManagement {
    repositories {
        maven("https://gitlab.com/api/v4/projects/68438621/packages/maven") // c2x Conventions
    }
}

plugins {
    id("de.connect2x.conventions.c2x-settings-plugin") version "20260606.144834" // https://gitlab.com/connect2x/c2x-conventions/-/packages
}

rootProject.name = "qca"

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

include(
    ":qca-crypto",
    ":qca-encoding",
    ":qca-idp",
    ":qca-raw",
    ":qca-nfc",
)

