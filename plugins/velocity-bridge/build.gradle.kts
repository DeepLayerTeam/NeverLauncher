plugins { java }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:proxy-family-common"))
    compileOnly("com.velocitypowered:velocity-api:3.4.0-SNAPSHOT")
}
tasks.jar {
    archiveBaseName.set("neverlauncher-velocity-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) } })
}


tasks.processResources {
    inputs.property("neverLauncherVersion", project.version.toString())
    filesMatching(listOf("plugin.yml", "velocity-plugin.json")) {
        expand("version" to project.version.toString())
    }
}
