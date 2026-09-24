plugins {
    java
    id("net.minecraftforge.gradle") version "7.0.31"
}
version = rootProject.file("VERSION").readText().trim()
group = "ru.neverlauncher"
base { archivesName.set("neverlauncher-forge-bridge") }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

minecraft {
    mappings("official", "1.21.1")
}

val bridgeRuntime by configurations.creating

dependencies {
    minecraft("net.minecraftforge:forge:1.21.1-52.1.16")
    implementation(project(":plugins:modloader-family-common"))
    bridgeRuntime(project(":plugins:modloader-family-common"))
}

tasks.jar {
    archiveBaseName.set("neverlauncher-forge-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({
        bridgeRuntime.map { if (it.isDirectory) it else zipTree(it) }
    })
    manifest {
        attributes["Implementation-Title"] = "NeverLauncher Forge Server Bridge"
        attributes["Implementation-Version"] = project.version.toString()
    }
}

tasks.processResources {
    inputs.property("neverLauncherVersion", project.version.toString())
    filesMatching("META-INF/mods.toml") { expand("version" to project.version.toString()) }
}
