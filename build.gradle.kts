plugins {
    `maven-publish`
    alias(libs.plugins.dokka)
    alias(libs.plugins.android.library).apply(false)
    alias(libs.plugins.kotlin.multiplatform).apply(false)
    alias(libs.plugins.kotlinx.serialization).apply(false)
}

allprojects {
    group = "de.connect2x"
    version = withVersionSuffix("0.0.1")

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

subprojects {
    if (project.name.startsWith("qca-")) {
        apply(plugin = "org.jetbrains.dokka")
        apply(plugin = "maven-publish")

        val dokkaJar by tasks.registering(Jar::class) {
            dependsOn(tasks.dokkaHtml)
            from(tasks.dokkaHtml.flatMap { it.outputDirectory })
            archiveClassifier.set("javadoc")
            onlyIf { isCI }
        }

        publishing {
            repositories {
                maven {
                    url = uri("${System.getenv("CI_API_V4_URL")}/projects/26519650/packages/maven")
                    name = "GitLab"
                    credentials(HttpHeaderCredentials::class) {
                        name = "Job-Token"
                        value = System.getenv("CI_JOB_TOKEN")
                    }
                    authentication {
                        create("header", HttpHeaderAuthentication::class)
                    }
                }
            }
            publications.configureEach {
                if (this is MavenPublication) {
                    pom {
                        name.set(project.name)
                        description.set("Multiplatform Kotlin SDK for gematik idp authentication using health care cards")
                        url.set("https://gitlab.com/connect2x/qca")
                        developers {
                            developer {
                                id.set("benkuly")
                            }
                        }
                        scm {
                            url.set("https://gitlab.com/connect2x/qca")
                        }
                    }
                    if (isCI) artifact(dokkaJar)
                }
            }
        }
    }
}