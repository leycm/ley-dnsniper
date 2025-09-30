dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            from(files("libs.versions.toml"))
        }
    }
}

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    plugins {}
}

rootProject.name = "ley-dnsniper"

include("common", "api", "gui")

project(":api").projectDir = file("sni-api")
project(":common").projectDir = file("sni-common")
project(":gui").projectDir = file("sni-gui")
