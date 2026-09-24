plugins { java }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:bungee-family-common"))
    compileOnly("net.md-5:bungeecord-api:1.21-R0.5-SNAPSHOT")
}
tasks.jar {
    archiveBaseName.set("neverlauncher-bungeecord-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) } })
}
tasks.processResources {
    inputs.property("neverLauncherVersion", project.version.toString())
    filesMatching("bungee.yml") { expand("version" to project.version.toString()) }
}
