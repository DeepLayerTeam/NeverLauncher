pluginManagement { repositories { maven("https://maven.fabricmc.net/"); maven("https://maven.minecraftforge.net/"); maven("https://maven.neoforged.net/releases/"); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories {
        mavenCentral()
        maven("https://maven.fabricmc.net/")
        maven("https://maven.minecraftforge.net/")
        maven("https://maven.neoforged.net/releases/")
        maven("https://repo.papermc.io/repository/maven-public/")
        maven("https://hub.spigotmc.org/nexus/content/repositories/snapshots/")
    }
}
rootProject.name = "NeverLauncher"
include("plugins:bridge-common")
include("plugins:proxy-family-common")
include("plugins:bungee-family-common")
include("plugins:velocity-bridge")
include("plugins:bungeecord-bridge")
include("plugins:waterfall-bridge")
include("plugins:paper-bridge")
include("plugins:purpur-bridge")

include("plugins:bukkit-family-common")
include("plugins:bukkit-bridge")
include("plugins:spigot-bridge")
include("plugins:folia-bridge")
include("plugins:fabric-bridge")
include("plugins:modloader-family-common")
include("plugins:forge-bridge")
include("plugins:neoforge-bridge")