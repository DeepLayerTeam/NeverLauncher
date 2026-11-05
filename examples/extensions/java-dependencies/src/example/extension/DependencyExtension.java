package example.extension;
import ru.launcher.sdk.core.Extension;
import ru.launcher.sdk.core.ExtensionContext;
import example.deps.Greeter;
public final class DependencyExtension implements Extension {
    public void start(ExtensionContext context){
        if(!"dependency-loaded-0482".equals(Greeter.greeting()))throw new IllegalStateException("Не удалось загрузить зависимость");
        System.out.println("Загружена настоящая JAR-зависимость расширения: "+Greeter.greeting());
    }
    public void stop(ExtensionContext context){}
}
