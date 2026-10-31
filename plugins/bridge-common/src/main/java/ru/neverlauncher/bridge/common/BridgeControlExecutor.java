package ru.launcher.bridge.common;

@FunctionalInterface
public interface BridgeControlExecutor {
    BridgeControlResult execute(BridgeControlCommand command) throws Exception;
}
