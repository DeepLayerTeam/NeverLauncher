pluginManagement { repositories { mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/")
        maven("https://hub.spigotmc.org/nexus/content/repositories/snapshots/")
    }
}
rootProject.name = "NeverLauncher"
include("plugins:bridge-common")
include("plugins:velocity-bridge")
include("plugins:paper-bridge")
include("plugins:purpur-bridge")

include("plugins:bukkit-family-common")
include("plugins:bukkit-bridge")
include("plugins:spigot-bridge")
include("plugins:folia-bridge")