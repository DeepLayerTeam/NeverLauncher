plugins { java }
version = rootProject.file("VERSION").readText().trim()
group = "ru.neverlauncher"
base { archivesName.set("neverlauncher-vanilla-bridge") }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

val bridgeRuntime = configurations.create("bridgeRuntime")
dependencies {
    implementation(project(":plugins:bridge-common"))
    add(bridgeRuntime.name, project(":plugins:bridge-common"))
}

tasks.jar {
    dependsOn(bridgeRuntime.buildDependencies)
    archiveBaseName.set("neverlauncher-vanilla-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ bridgeRuntime.map { if (it.isDirectory) it else zipTree(it) } })
    manifest {
        attributes["Main-Class"] = "ru.neverlauncher.bridge.vanilla.NeverLauncherVanillaBridge"
        attributes["Implementation-Title"] = "NeverLauncher Vanilla Server Bridge"
        attributes["Implementation-Version"] = project.version.toString()
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.encoding = "UTF-8"
}
