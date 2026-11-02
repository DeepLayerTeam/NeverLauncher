package ru.launcher.sdk.core;

import java.util.Objects;

/** Public SPI contract identity; version is independent of the host wire protocol. */
public record ProviderService<T extends JavaProvider>(String id, Class<T> type, SemVer version) {
    public ProviderService {
        if (id == null || !id.matches("[a-z][a-z0-9._-]{2,79}"))
            throw new IllegalArgumentException("invalid SPI service id");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(version, "version");
        if (!type.isInterface() || !JavaProvider.class.isAssignableFrom(type))
            throw new IllegalArgumentException("SPI contract must be an interface extending JavaProvider");
    }
}
