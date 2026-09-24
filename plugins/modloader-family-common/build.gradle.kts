plugins { `java-library` }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    api(project(":plugins:bridge-common"))
    compileOnly("org.slf4j:slf4j-api:2.0.16")
}
