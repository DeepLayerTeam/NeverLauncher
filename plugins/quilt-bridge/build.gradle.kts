plugins {
    id("net.fabricmc.fabric-loom-remap") version "1.17.21"
}

version = rootProject.file("VERSION").readText().trim()
group = "ru.neverlauncher"
base { archivesName.set("neverlauncher-quilt-bridge") }

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
    withSourcesJar()
}

repositories {
    maven("https://maven.quiltmc.org/repository/release/")
    maven("https://maven.fabricmc.net/")
    mavenCentral()
}

dependencies {
    minecraft("com.mojang:minecraft:1.21.1")
    mappings("net.fabricmc:yarn:1.21.1+build.3:v2")
    modImplementation("org.quiltmc:quilt-loader:0.26.4")
    // QFAPI exposes the Fabric-compatible event/networking APIs used by this adapter.
    modImplementation("org.quiltmc.quilted-fabric-api:quilted-fabric-api:11.0.0-alpha.3+0.102.0-1.21")

    implementation(project(":plugins:bridge-common"))
    include(project(":plugins:bridge-common"))
}

tasks.processResources {
    inputs.property("neverLauncherVersion", project.version.toString())
    filesMatching(listOf("fabric.mod.json", "quilt.mod.json")) {
        expand("version" to project.version.toString())
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.encoding = "UTF-8"
}
