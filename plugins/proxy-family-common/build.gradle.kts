plugins { java }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:bridge-common"))
}
