plugins { java }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:bukkit-family-common"))
    compileOnly("org.spigotmc:spigot-api:1.21.1-R0.1-SNAPSHOT")
}
tasks.jar {
    dependsOn(configurations.runtimeClasspath.get().buildDependencies)
    archiveBaseName.set("neverlauncher-folia-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) } })
}
tasks.processResources {
    inputs.property("neverLauncherVersion", project.version.toString())
    filesMatching("plugin.yml") {
        expand("version" to project.version.toString())
    }
}
