plugins {
    `java-library`
    id("net.neoforged.moddev") version "2.0.147"
}
version = rootProject.file("VERSION").readText().trim()
group = "ru.launcher"
base { archivesName.set("launcher-neoforge-bridge") }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

neoForge {
    version = "21.1.251"
    mods {
        create("launcher_serverbridge") {
            sourceSet(sourceSets.main.get())
        }
    }
}

val bridgeRuntime = configurations.create("bridgeRuntime")

dependencies {
    implementation(project(":plugins:modloader-family-common"))
    add(bridgeRuntime.name, project(":plugins:modloader-family-common"))
}

tasks.jar {
    dependsOn(bridgeRuntime.buildDependencies)
    archiveBaseName.set("launcher-neoforge-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({
        bridgeRuntime.map { if (it.isDirectory) it else zipTree(it) }
    })
    manifest {
        attributes["Implementation-Title"] = "Launcher NeoForge Server Bridge"
        attributes["Implementation-Version"] = project.version.toString()
    }
}

tasks.processResources {
    inputs.property("LauncherVersion", project.version.toString())
    filesMatching("META-INF/neoforge.mods.toml") { expand("version" to project.version.toString()) }
}
