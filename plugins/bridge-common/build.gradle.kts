plugins { `java-library` }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

val generatedVersionDir = layout.buildDirectory.dir("generated/sources/version/java")
val generateVersionSource by tasks.registering {
    inputs.property("LauncherVersion", project.version.toString())
    outputs.dir(generatedVersionDir)
    doLast {
        val file = generatedVersionDir.get().file("ru/launcher/bridge/common/BridgeVersion.java").asFile
        file.parentFile.mkdirs()
        file.writeText(
            """package ru.launcher.bridge.common;
public final class BridgeVersion {
    public static final String VERSION = "${project.version}";
    private BridgeVersion() {}
}
"""
        )
    }
}
sourceSets.main { java.srcDir(generatedVersionDir) }
tasks.named("compileJava") { dependsOn(generateVersionSource) }
