package ru.launcher.trusted;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/** Обёртка без изменений вызывает исходную точку входа Minecraft, окружённую
 *  доверенными хуками. afterMinecraftMain означает ПОСЛЕ возврата из main, а не «загрузка мира завершена». */
public final class MinecraftMain {
    private MinecraftMain() { }
    public static void main(String[] args) throws Throwable {
        String entry = Agent.mainClass();
        if (entry.equals(MinecraftMain.class.getName())) throw new IllegalStateException("Обнаружен рекурсивный вызов точки входа Minecraft");
        Throwable failure = null;
        try {
            Agent.beforeMain(args);
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            Class<?> game = Class.forName(entry,true,loader);
            Method method = game.getMethod("main",String[].class);
            method.invoke(null,(Object)args);
        } catch (InvocationTargetException e) {
            failure=e.getCause(); throw failure;
        } catch (Throwable t) { failure=t; throw t;
        } finally {
            try { Agent.afterMain(failure); }
            catch (Throwable after) {
                if (failure != null) failure.addSuppressed(after);
                else throw after;
            }
        }
    }
}
