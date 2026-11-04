package ru.launcher.sdk.gravit;
import java.lang.annotation.*;
/** Явная привязка Go EventBus: неподдерживаемые классы событий отклоняются при init. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface HostEvent { String type(); String mode() default "async"; }
