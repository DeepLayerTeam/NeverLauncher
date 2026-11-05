package pro.gravit.utils.command;
import java.util.*;
/** Команда в формате Gravit; выполнение делегируется подписанному CLI Extensions. */
public abstract class Command {
    public final Map<String,Command> childCommands=new HashMap<>();
    public abstract String getArgsDescription();
    public abstract String getUsageDescription();
    public abstract void invoke(String... args) throws Exception;
    protected final void verifyArgs(String[] args,int minimum){if(args.length<minimum)throw new IllegalArgumentException("Использование: "+getArgsDescription());}
    public final void invokeSubcommands(String... args)throws Exception {
        verifyArgs(args,1);Command next=childCommands.get(args[0]);if(next==null)throw new IllegalArgumentException("Неизвестная подкоманда");
        next.invoke(Arrays.copyOfRange(args,1,args.length));
    }
}
