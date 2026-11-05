package ru.launcher.sdk.core;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

/** Монотонный крайний срок, не зависящий от изменения системных часов. */
public final class Deadline {
    private final long start=System.nanoTime();private final long nanos;
    private Deadline(Duration duration){if(duration.isZero()||duration.isNegative())throw new IllegalArgumentException("Срок ожидания должен быть положительным");nanos=duration.toNanos();}
    public static Deadline after(Duration duration){return new Deadline(duration);}
    public Duration remaining(){long elapsed=System.nanoTime()-start;return Duration.ofNanos(Math.max(0,nanos-Math.max(elapsed,0)));}
    public boolean expired(){return remaining().isZero();}
    public void check() throws TimeoutException{if(expired())throw new TimeoutException("Превышено время выполнения операции расширения");}
}
