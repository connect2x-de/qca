plugins {
    alias(libs.plugins.android.library).apply(false)
    alias(libs.plugins.kotlin.multiplatform).apply(false)
    alias(libs.plugins.kotlinx.serialization).apply(false)
}

allprojects {
    group = "de.connect2x"
    version = withVersionSuffix("2.0.0")

    repositories {
        mavenLocal()
        google()
        mavenCentral()
        maven("https://oss.sonatype.org/content/repositories/snapshots")
        maven("https://gitlab.com/api/v4/projects/26519650/packages/maven")
    }

    dependencyLocking {
        lockMode = LockMode.LENIENT
        lockAllConfigurations()
    }

    val dependenciesForAll by tasks.registering(DependencyReportTask::class) { }
}
