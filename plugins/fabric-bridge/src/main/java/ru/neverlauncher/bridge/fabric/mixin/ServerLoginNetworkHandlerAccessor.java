package ru.neverlauncher.bridge.fabric.mixin;

import com.mojang.authlib.GameProfile;
import net.minecraft.network.ClientConnection;
import net.minecraft.server.network.ServerLoginNetworkHandler;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(ServerLoginNetworkHandler.class)
public interface ServerLoginNetworkHandlerAccessor {
    @Accessor("profile")
    GameProfile neverlauncher$getProfile();

    @Accessor("profileName")
    String neverlauncher$getProfileName();

    @Accessor("connection")
    ClientConnection neverlauncher$getConnection();
}
