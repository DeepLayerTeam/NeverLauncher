plugins { java }
version = rootProject.file("VERSION").readText().trim()
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    implementation(project(":plugins:proxy-family-common"))
    compileOnly("net.md-5:bungeecord-api:1.21-R0.5-SNAPSHOT")
}
