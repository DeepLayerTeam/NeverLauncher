package ru.launcher.sdk.gravit;
import java.lang.annotation.*;
/** Explicit Go EventBus binding: unsupported event classes are rejected during init. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface HostEvent { String type(); String mode() default "async"; }
