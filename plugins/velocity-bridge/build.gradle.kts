plugins { java }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:bridge-common"))
    compileOnly("com.velocitypowered:velocity-api:3.4.0-SNAPSHOT")
}
tasks.jar {
    archiveBaseName.set("neverlauncher-velocity-bridge")
    archiveVersion.set("0.10.4")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from({ configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) } })
}
