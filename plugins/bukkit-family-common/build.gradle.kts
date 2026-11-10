plugins { `java-library` }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    api(project(":plugins:bridge-common"))
    compileOnly("org.spigotmc:spigot-api:26.3-R0.1-SNAPSHOT")
}
