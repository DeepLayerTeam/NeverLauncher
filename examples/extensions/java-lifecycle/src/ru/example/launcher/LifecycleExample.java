package ru.example.launcher;

import ru.launcher.sdk.core.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Настоящий пример жизненного цикла. Backend контролирует эту JVM как обычный процесс Extensions. */
public final class LifecycleExample implements Extension {
    private final AtomicBoolean started=new AtomicBoolean();
    @Override public void start(ExtensionContext context) throws Exception {
        context.checkActive();
        if(!started.compareAndSet(false,true))throw new IllegalStateException("Повторный запуск");
        System.out.println("Java-расширение запущено: "+context.manifest().id());
        context.cancellation().onCancel(()->System.out.println("Запрошена отмена Java-расширения"));
    }
    @Override public void stop(ExtensionContext context) {
        if(started.compareAndSet(true,false))System.out.println("Java-расширение остановлено: "+context.manifest().id());
    }
}
