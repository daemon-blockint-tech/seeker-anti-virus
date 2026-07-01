pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven("https://solanamobile.jfrog.io/artifactory/maven")
    }
}

rootProject.name = "sync-android"

include(":app")
include(":engine")
include(":yara-native")
