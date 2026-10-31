#!/bin/sh
set -eu
cd "$(dirname "$0")"
sh ../../../sdk/java/trusted-agent/build.sh
mkdir -p build/classes build/plugin-classes build/game-classes build/package/trusted/plugins
javac --release 8 -cp ../../../sdk/java/trusted-agent/build/agent.jar -d build/plugin-classes src/example/LoggingHook.java
mkdir -p build/plugin-classes/META-INF/services
printf '%s\n' 'example.LoggingHook' > build/plugin-classes/META-INF/services/ru.launcher.trusted.MinecraftHook
jar cf build/package/trusted/plugins/logging-hook.jar -C build/plugin-classes .
cp ../../../sdk/java/trusted-agent/build/agent.jar build/package/trusted/agent.jar
javac --release 8 -d build/game-classes src/example/FixtureGame.java src/net/minecraft/client/Minecraft.java
jar cf build/game.jar -C build/game-classes .
cp launcher-extension.json build/package/launcher-extension.json
