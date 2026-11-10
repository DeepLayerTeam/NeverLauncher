plugins { java }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:proxy-family-common"))
    compileOnly("net.md-5:bungeecord-api:26.1-R0.1-SNAPSHOT")
}
