plugins { java }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:bungee-family-common"))
    compileOnly("net.md-5:bungeecord-api:26.1-R0.1-SNAPSHOT")
}
tasks.jar {
    dependsOn(configurations.runtimeClasspath.get().buildDependencies)
    archiveBaseName.set("launcher-waterfall-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) } })
}
tasks.processResources {
    inputs.property("LauncherVersion", project.version.toString())
    filesMatching("bungee.yml") { expand("version" to project.version.toString()) }
}
