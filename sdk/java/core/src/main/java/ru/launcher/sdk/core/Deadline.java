package ru.launcher.sdk.core;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

/** Monotonic deadline; immune to wall-clock adjustments. */
public final class Deadline {
    private final long start=System.nanoTime();private final long nanos;
    private Deadline(Duration duration){if(duration.isZero()||duration.isNegative())throw new IllegalArgumentException("deadline must be positive");nanos=duration.toNanos();}
    public static Deadline after(Duration duration){return new Deadline(duration);}
    public Duration remaining(){long elapsed=System.nanoTime()-start;return Duration.ofNanos(Math.max(0,nanos-Math.max(elapsed,0)));}
    public boolean expired(){return remaining().isZero();}
    public void check() throws TimeoutException{if(expired())throw new TimeoutException("extension operation deadline exceeded");}
}
