package ru.example.gravit;

import java.util.Map;
import pro.gravit.launcher.base.modules.*;
import pro.gravit.utils.Version;
import pro.gravit.utils.command.Command;
import pro.gravit.utils.command.CommandHandler;
import ru.launcher.sdk.gravit.*;

/** Функциональный порт в формате Gravit: события и CLI работают с настоящим хостом Go. */
public final class PortedModule extends LauncherModule implements AutoCloseable {
    private GravitInitContext context;
    public PortedModule(){super(new LauncherModuleInfoBuilder().setName("PortedAudit").setVersion(new Version(1,0,0,0,Version.Type.LTS)).createLauncherModuleInfo());}
    @Override public void init(LauncherInitContext initContext){
        if(!(initContext instanceof GravitInitContext ctx))throw new IllegalStateException("Launcher context required");
        context=ctx;
        if("backend".equals(System.getenv("LAUNCHER_EXTENSION_TARGET")))registerEvent(this::onRelease,ReleasePublishedEvent.class);
        modulesManager.getCommandHandler().registerCommand("status",new Command(){
            @Override public String getArgsDescription(){return "";}
            @Override public String getUsageDescription(){return "Reports the latest release event";}
            @Override public void invoke(String... args)throws Exception {
                if(args.length!=0)throw new IllegalArgumentException("status takes no arguments");
                Object state=ctx.extension().runtime().storage().get("last-release",null).orElse(Map.of());
                // Вызов Gravit void invoke() преобразуется в структурированный ответ Extensions CLI.
                CommandHandler.respond(Map.of("latestRelease",state));
            }
        });
    }
    private void onRelease(ReleasePublishedEvent event) {
        try {context.extension().runtime().storage().put("last-release",Map.of("eventId",event.id,"projectId",event.projectId,"payload",event.payload),null);}
        catch(Exception e){throw new IllegalStateException("Не удалось сохранить событие релиза",e);}
    }
    @Override public void close(){context=null;}
}
