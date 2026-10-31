package ru.launcher.sdk.core;

import java.util.*;
import java.util.concurrent.CancellationException;

/** Thread-safe cooperative cancellation with exactly-once callbacks and parent linkage. */
public final class Cancellation implements AutoCloseable {
    private boolean cancelled;
    private final List<Runnable> listeners=new ArrayList<>();
    public boolean isCancelled(){synchronized(this){return cancelled;}}
    public void throwIfCancelled(){if(isCancelled())throw new CancellationException("extension operation cancelled");}
    public AutoCloseable onCancel(Runnable callback){
        Objects.requireNonNull(callback);
        synchronized(this){if(!cancelled){listeners.add(callback);return ()->{synchronized(this){listeners.remove(callback);}};}}
        callback.run();return ()->{};
    }
    public boolean cancel(){
        List<Runnable> pending;
        synchronized(this){if(cancelled)return false;cancelled=true;pending=List.copyOf(listeners);listeners.clear();}
        for(Runnable callback:pending){try{callback.run();}catch(RuntimeException ignored){/* independent callbacks must still run */}}
        return true;
    }
    public Cancellation child(){Cancellation child=new Cancellation();onCancel(child::cancel);return child;}
    @Override public void close(){cancel();}
}
