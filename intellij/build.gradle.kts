plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "1.9.21"
    id("org.jetbrains.intellij") version "1.16.1"
}

group = "com.craniumai"
version = "1.0.1"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib")
    testImplementation("junit:junit:4.13.2")
}

intellij {
    version.set("2023.1.5")
    type.set("IC") // IC = IntelliJ IDEA Community, IU = Ultimate
    plugins.set(listOf(/* Add plugin dependencies here if needed */))
}

tasks {
    withType<JavaCompile> {
        sourceCompatibility = "17"
        targetCompatibility = "17"
    }

    withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
        kotlinOptions.jvmTarget = "17"
    }

    patchPluginXml {
        sinceBuild.set("231")
        untilBuild.set("253.*")
        version.set(project.version.toString())
    }

    prepareSandbox {
        from("LICENSE.txt") {
            into("${intellij.pluginName.get()}")
        }
        from("README.md") {
            into("${intellij.pluginName.get()}")
        }
        from("ENDPOINT_ALLOWLIST.md") {
            into("${intellij.pluginName.get()}")
        }
    }

    signPlugin {
        certificateChainFile.set(file("chain.crt"))
        privateKeyFile.set(file("private.pem"))
        password.set("")
    }

    publishPlugin {
        token.set(System.getenv("PUBLISH_TOKEN"))
    }
}
