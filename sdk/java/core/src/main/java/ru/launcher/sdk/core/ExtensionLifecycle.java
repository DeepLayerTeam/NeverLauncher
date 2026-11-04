package ru.launcher.sdk.core;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Ограниченный по времени и отменяемый жизненный цикл расширения; зависший обратный вызов не блокирует управляющий поток. */
public final class ExtensionLifecycle implements AutoCloseable {
    public enum State { NEW, STARTING, RUNNING, STOPPING, STOPPED, FAILED }
    private static final AtomicInteger IDS=new AtomicInteger();
    private final Extension extension;
    private final ExtensionManifest manifest;
    private final RuntimeServices runtime;
    private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{
        Thread t=new Thread(r,"neverext-lifecycle-"+IDS.incrementAndGet());t.setDaemon(true);return t;
    });
    private final Cancellation cancellation=new Cancellation();
    private final ProviderRegistry providers;
    private final Object transition=new Object();
    private volatile State state=State.NEW;
    private Future<?> active;
    private final CountDownLatch stopFinished=new CountDownLatch(1);

    public ExtensionLifecycle(Extension extension,ExtensionManifest manifest){this(extension,manifest,null);}
    public ExtensionLifecycle(Extension extension,ExtensionManifest manifest,RuntimeServices runtime){
        this.extension=Objects.requireNonNull(extension);this.manifest=Objects.requireNonNull(manifest);this.runtime=runtime;
        this.providers=new ProviderRegistry(manifest,runtime,cancellation);
        if(runtime!=null){runtime.identity().bind(providers);runtime.content().bind(providers);}
    }
    public State state(){return state;}
    public void start(Duration timeout) throws Exception {
        validateTimeout(timeout);
        synchronized(transition){
            if(state!=State.NEW)throw new IllegalStateException("cannot start in state "+state);
            state=State.STARTING;
        }
        try {
            invoke(()->extension.start(new ExtensionContext(manifest,cancellation,Deadline.after(timeout),runtime,providers)),timeout,State.STARTING);
            synchronized(transition){
                if(state!=State.STARTING)throw new CancellationException("extension startup cancelled");
                state=State.RUNNING;
            }
        }catch(Exception e){
            synchronized(transition){if(state!=State.STOPPED)state=State.FAILED;}
            cancellation.cancel();
            try{providers.shutdown(Duration.ofMillis(500));}catch(Exception cleanup){e.addSuppressed(cleanup);}
            executor.shutdownNow();throw e;
        }
    }
    public void stop(Duration timeout) throws Exception {
        validateTimeout(timeout);
        State previous;
        synchronized(transition){
            previous=state;
            if(previous==State.STOPPED)return;
            if(previous==State.STOPPING){
                // Первый вызывающий поток владеет stop(); параллельные вызовы не должны
                // закрывать службы SDK до окончания его обратного вызова.
            }else if(previous==State.NEW||previous==State.STARTING||previous==State.FAILED){
                state=State.STOPPED;
                if(active!=null)active.cancel(true);
            }else if(previous==State.RUNNING){state=State.STOPPING;}
            else if(previous!=State.STOPPING)throw new IllegalStateException("cannot stop in state "+state);
        }
        if(previous==State.STOPPING){
            if(!stopFinished.await(timeout.toNanos(),TimeUnit.NANOSECONDS))
                throw new TimeoutException("concurrent extension stop deadline exceeded");
            if(state==State.FAILED)throw new IllegalStateException("extension stop failed");
            return;
        }
        cancellation.cancel();
        if(previous!=State.RUNNING){
            try{providers.shutdown(timeout);}
            catch(Exception failure){
                synchronized(transition){state=State.FAILED;}
                throw failure;
            }finally{executor.shutdownNow();stopFinished.countDown();}
            return;
        }
        long started=System.nanoTime();
        Exception failure=null;
        try {
            invoke(()->extension.stop(new ExtensionContext(manifest,cancellation,Deadline.after(timeout),runtime,providers)),timeout,State.STOPPING);
        }catch(Exception e){ failure=e; }
        try {
            long remaining=timeout.toNanos()-(System.nanoTime()-started);
            providers.shutdown(Duration.ofNanos(Math.max(1,remaining)));
        }catch(Exception e){if(failure==null)failure=e;else failure.addSuppressed(e);}
        synchronized(transition){if(state==State.STOPPING)state=failure==null?State.STOPPED:State.FAILED;}
        executor.shutdownNow();stopFinished.countDown();
        if(failure!=null)throw failure;
    }
    private static void validateTimeout(Duration timeout){
        Objects.requireNonNull(timeout,"timeout");
        if(timeout.isZero()||timeout.isNegative())throw new IllegalArgumentException("timeout must be positive");
    }
    private void invoke(CheckedAction action,Duration timeout,State expected) throws Exception {
        long nanos=timeout.toNanos();
        Future<?> task;
        synchronized(transition){
            if(state!=expected)throw new CancellationException("extension lifecycle cancelled");
            task=executor.submit(()->{try{action.run();}catch(Exception e){throw new CompletionException(e);}});
            active=task;
        }
        try{task.get(nanos,TimeUnit.NANOSECONDS);}
        catch(TimeoutException e){task.cancel(true);throw new TimeoutException("extension lifecycle deadline exceeded");}
        catch(InterruptedException e){task.cancel(true);Thread.currentThread().interrupt();throw e;}
        catch(ExecutionException e){
            Throwable root=e.getCause();
            if(root instanceof CompletionException&&root.getCause()!=null)root=root.getCause();
            if(root instanceof Exception ex)throw ex;
            throw new IllegalStateException("extension lifecycle failed",root);
        }finally{
            synchronized(transition){if(active==task)active=null;}
        }
    }
    private interface CheckedAction{void run() throws Exception;}
    @Override public void close(){
        try{stop(Duration.ofSeconds(3));}
        catch(Exception ignored){cancellation.cancel();executor.shutdownNow();}
    }
}
