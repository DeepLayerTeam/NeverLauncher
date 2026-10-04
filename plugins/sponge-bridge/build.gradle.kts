plugins { java }
version = rootProject.file("VERSION").readText().trim()
group = "ru.neverlauncher"
base { archivesName.set("neverlauncher-sponge-bridge") }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
repositories {
    maven("https://repo.spongepowered.org/repository/maven-public/")
    mavenCentral()
}
val bridgeRuntime = configurations.create("bridgeRuntime")
dependencies {
    compileOnly("org.spongepowered:spongeapi:12.0.0")
    implementation(project(":plugins:bridge-common"))
    add(bridgeRuntime.name, project(":plugins:bridge-common"))
}
tasks.jar {
    dependsOn(bridgeRuntime.buildDependencies)
    archiveBaseName.set("neverlauncher-sponge-bridge")
    archiveVersion.set(project.version.toString())
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ bridgeRuntime.map { if (it.isDirectory) it else zipTree(it) } })
    manifest {
        attributes["Implementation-Title"] = "NeverLauncher Sponge Server Bridge"
        attributes["Implementation-Version"] = project.version.toString()
    }
}
tasks.withType<JavaCompile>().configureEach { options.release.set(21); options.encoding = "UTF-8" }
