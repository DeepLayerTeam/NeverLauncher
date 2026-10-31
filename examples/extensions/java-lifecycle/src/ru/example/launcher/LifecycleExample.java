package ru.example.launcher;

import ru.launcher.sdk.core.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Real lifecycle example. The backend supervises this JVM as an ordinary Extensions process. */
public final class LifecycleExample implements Extension {
    private final AtomicBoolean started=new AtomicBoolean();
    @Override public void start(ExtensionContext context) throws Exception {
        context.checkActive();
        if(!started.compareAndSet(false,true))throw new IllegalStateException("started twice");
        System.out.println("Java extension started: "+context.manifest().id());
        context.cancellation().onCancel(()->System.out.println("Java extension cancellation requested"));
    }
    @Override public void stop(ExtensionContext context) {
        if(started.compareAndSet(true,false))System.out.println("Java extension stopped: "+context.manifest().id());
    }
}
