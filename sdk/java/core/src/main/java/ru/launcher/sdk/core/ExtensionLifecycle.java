package ru.launcher.sdk.core;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Executes lifecycle callbacks with interruption, deadlines, state transitions and bounded waits. */
public final class ExtensionLifecycle implements AutoCloseable {
    public enum State { NEW, STARTING, RUNNING, STOPPING, STOPPED, FAILED }
    private static final AtomicInteger IDS=new AtomicInteger();
    private final Extension extension;
    private final ExtensionManifest manifest;
    private final RuntimeServices runtime;
    private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"neverext-lifecycle-"+IDS.incrementAndGet());t.setDaemon(true);return t;});
    private final Cancellation cancellation=new Cancellation();
    private State state=State.NEW;
    public ExtensionLifecycle(Extension extension,ExtensionManifest manifest){this.extension=Objects.requireNonNull(extension);this.manifest=Objects.requireNonNull(manifest);this.runtime=null;}
    public ExtensionLifecycle(Extension extension,ExtensionManifest manifest,RuntimeServices runtime){this.extension=Objects.requireNonNull(extension);this.manifest=Objects.requireNonNull(manifest);this.runtime=Objects.requireNonNull(runtime);}
    public synchronized State state(){return state;}
    public synchronized void start(Duration timeout) throws Exception {
        if(state!=State.NEW)throw new IllegalStateException("cannot start in state "+state);
        state=State.STARTING;
        try{invoke(()->extension.start(new ExtensionContext(manifest,cancellation,Deadline.after(timeout),runtime)),timeout);state=State.RUNNING;}
        catch(Exception e){state=State.FAILED;cancellation.cancel();executor.shutdownNow();throw e;}
    }
    public synchronized void stop(Duration timeout) throws Exception {
        if(state==State.STOPPED)return;
        if(state==State.NEW){state=State.STOPPED;cancellation.cancel();executor.shutdownNow();return;}
        if(state!=State.RUNNING)throw new IllegalStateException("cannot stop in state "+state);
        state=State.STOPPING;cancellation.cancel();
        try{invoke(()->extension.stop(new ExtensionContext(manifest,cancellation,Deadline.after(timeout),runtime)),timeout);state=State.STOPPED;}
        catch(Exception e){state=State.FAILED;throw e;}
        finally{executor.shutdownNow();}
    }
    private void invoke(CheckedAction action,Duration timeout) throws Exception {
        long nanos=timeout.toNanos();if(nanos<=0)throw new IllegalArgumentException("timeout must be positive");
        Future<?> task=executor.submit(()->{try{action.run();}catch(Exception e){throw new CompletionException(e);}});
        try{task.get(nanos,TimeUnit.NANOSECONDS);}
        catch(TimeoutException e){task.cancel(true);throw new TimeoutException("extension lifecycle deadline exceeded");}
        catch(InterruptedException e){task.cancel(true);Thread.currentThread().interrupt();throw e;}
        catch(ExecutionException e){Throwable root=e.getCause();if(root instanceof CompletionException&&root.getCause()!=null)root=root.getCause();if(root instanceof Exception ex)throw ex;throw new IllegalStateException("extension lifecycle failed",root);}
    }
    private interface CheckedAction{void run() throws Exception;}
    @Override public synchronized void close(){
        if(state==State.RUNNING){try{stop(Duration.ofSeconds(3));}catch(Exception ignored){/* untrusted callback: caller observes FAILED state */}}
        else{cancellation.cancel();executor.shutdownNow();}
    }
}
