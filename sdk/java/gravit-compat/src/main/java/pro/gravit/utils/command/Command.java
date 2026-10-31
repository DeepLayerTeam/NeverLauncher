package pro.gravit.utils.command;
import java.util.*;
/** Callable Gravit-shaped command; execution delegates to the signed Extensions CLI. */
public abstract class Command {
    public final Map<String,Command> childCommands=new HashMap<>();
    public abstract String getArgsDescription();
    public abstract String getUsageDescription();
    public abstract void invoke(String... args) throws Exception;
    protected final void verifyArgs(String[] args,int minimum){if(args.length<minimum)throw new IllegalArgumentException("Usage: "+getArgsDescription());}
    public final void invokeSubcommands(String... args)throws Exception {
        verifyArgs(args,1);Command next=childCommands.get(args[0]);if(next==null)throw new IllegalArgumentException("unknown subcommand");
        next.invoke(Arrays.copyOfRange(args,1,args.length));
    }
}
