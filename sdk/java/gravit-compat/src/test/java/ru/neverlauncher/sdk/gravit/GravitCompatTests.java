package ru.launcher.sdk.gravit;
import java.util.*;
import pro.gravit.launcher.base.modules.*;
import pro.gravit.utils.Version;
import pro.gravit.utils.command.Command;

public final class GravitCompatTests {
    static int passed;
    static void verify(boolean value){if(!value)throw new AssertionError("assertion failed");passed++;}
    static void rejected(Runnable callback){try{callback.run();throw new AssertionError("should reject");}catch(IllegalArgumentException|IllegalStateException|UnsupportedOperationException|NullPointerException expected){passed++;}}
    static class Mod extends LauncherModule {
        boolean pre,init;
        Mod(){super(new LauncherModuleInfoBuilder().setName("ValidModule").setVersion(new Version(1,2,3,4,Version.Type.LTS)).createLauncherModuleInfo());}
        public void preInitAction(){pre=true;}
        public void init(LauncherInitContext context){verify(pre);init=true;}
    }
    public static void main(String[] args) throws Exception {
        Version one=new Version(1,2,3,4,Version.Type.LTS),two=new Version(1,2,4,0,Version.Type.LTS);
        verify(one.isLowerThan(two));verify(one.getVersionString().equals("1.2.3.4"));
        rejected(()->new Version(-1,2,3,4,Version.Type.LTS));
        rejected(()->new LauncherModuleInfoBuilder().setName("bad spaces").createLauncherModuleInfo());
        Mod mod=new Mod();verify(mod.getInitStatus()==LauncherModule.InitStatus.CREATED);
        // Only a ported extension bootstrap can provide a real host manager/context.
        rejected(()->mod.initialize(null,null));
        verify(mod.getInitStatus()==LauncherModule.InitStatus.CREATED);
        rejected(()->new LauncherModule.Event().cancel());
        Command cmd=new Command(){public String getArgsDescription(){return "<a>";}public String getUsageDescription(){return "test";}public void invoke(String... args){verify(args.length==1);}};
        cmd.childCommands.put("sub",cmd);
        cmd.invokeSubcommands("sub","value");
        rejected(()->{try{cmd.invokeSubcommands("missing");}catch(Exception e){throw new IllegalArgumentException(e);}});
        System.out.println("PASS: "+passed+" Gravit compatibility API checks");
    }
}
