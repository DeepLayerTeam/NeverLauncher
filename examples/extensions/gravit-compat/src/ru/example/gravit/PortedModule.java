package ru.example.gravit;

import java.util.Map;
import pro.gravit.launcher.base.modules.*;
import pro.gravit.utils.Version;
import pro.gravit.utils.command.Command;
import pro.gravit.utils.command.CommandHandler;
import ru.neverlauncher.sdk.gravit.*;

/** A functional Gravit-shaped port: events and CLI run against the real Go host. */
public final class PortedModule extends LauncherModule implements AutoCloseable {
    private GravitInitContext context;
    public PortedModule(){super(new LauncherModuleInfoBuilder().setName("PortedAudit").setVersion(new Version(1,0,0,0,Version.Type.LTS)).createLauncherModuleInfo());}
    @Override public void init(LauncherInitContext initContext){
        if(!(initContext instanceof GravitInitContext ctx))throw new IllegalStateException("NeverLauncher context required");
        context=ctx;
        if("backend".equals(System.getenv("NEVERLAUNCHER_EXTENSION_TARGET")))registerEvent(this::onRelease,ReleasePublishedEvent.class);
        modulesManager.getCommandHandler().registerCommand("status",new Command(){
            @Override public String getArgsDescription(){return "";}
            @Override public String getUsageDescription(){return "Reports the latest release event";}
            @Override public void invoke(String... args)throws Exception {
                if(args.length!=0)throw new IllegalArgumentException("status takes no arguments");
                Object state=ctx.extension().runtime().storage().get("last-release",null).orElse(Map.of());
                // Gravit's void invoke() is bridged to a structured NeverExtensions CLI response.
                CommandHandler.respond(Map.of("latestRelease",state));
            }
        });
    }
    private void onRelease(ReleasePublishedEvent event) {
        try {context.extension().runtime().storage().put("last-release",Map.of("eventId",event.id,"projectId",event.projectId,"payload",event.payload),null);}
        catch(Exception e){throw new IllegalStateException("failed to persist release event",e);}
    }
    @Override public void close(){context=null;}
}
