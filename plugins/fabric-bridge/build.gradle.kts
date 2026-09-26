plugins {
    id("net.fabricmc.fabric-loom-remap") version "1.17.21"
}

version = rootProject.file("VERSION").readText().trim()
group = "ru.neverlauncher"
base { archivesName.set("neverlauncher-fabric-bridge") }

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
    withSourcesJar()
}

dependencies {
    minecraft("com.mojang:minecraft:1.21.1")
    mappings("net.fabricmc:yarn:1.21.1+build.3:v2")
    modImplementation("net.fabricmc:fabric-loader:0.16.14")
    modImplementation("net.fabricmc.fabric-api:fabric-api:0.116.17+1.21.1")

    implementation(project(":plugins:bridge-common"))
    include(project(":plugins:bridge-common"))
}

tasks.processResources {
    inputs.property("neverLauncherVersion", project.version.toString())
    filesMatching("fabric.mod.json") {
        expand("version" to project.version.toString())
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.encoding = "UTF-8"
}
