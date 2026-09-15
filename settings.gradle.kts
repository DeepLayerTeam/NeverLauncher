pluginManagement { repositories { mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { mavenCentral(); maven("https://repo.papermc.io/repository/maven-public/") } }
rootProject.name = "NeverLauncher"
include("plugins:bridge-common")
include("plugins:velocity-bridge")
include("plugins:paper-bridge")
include("plugins:purpur-bridge")
