plugins { java }
version = rootProject.file("VERSION").readText().trim()
group = "ru.launcher"
base { archivesName.set("launcher-vanilla-bridge") }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

val bridgeRuntime = configurations.create("bridgeRuntime")
dependencies {
    implementation(project(":plugins:bridge-common"))
    add(bridgeRuntime.name, project(":plugins:bridge-common"))
}

tasks.jar {
    dependsOn(bridgeRuntime.buildDependencies)
    archiveBaseName.set("launcher-vanilla-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ bridgeRuntime.map { if (it.isDirectory) it else zipTree(it) } })
    manifest {
        attributes["Main-Class"] = "ru.launcher.bridge.vanilla.LauncherVanillaBridge"
        attributes["Implementation-Title"] = "Launcher Vanilla Server Bridge"
        attributes["Implementation-Version"] = project.version.toString()
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.encoding = "UTF-8"
}
