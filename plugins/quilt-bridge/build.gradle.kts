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
    // Match the Minecraft 1.21.1 Yarn mappings used by the bridge sources.
    // The QFAPI alpha here targets 1.21.0 and resolves incompatible Minecraft
    // classes. The Fabric API implements the events used by this adapter.
    modImplementation("net.fabricmc.fabric-api:fabric-api:0.116.17+1.21.1")
    compileOnly("org.spongepowered:mixin:0.8.7")

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
