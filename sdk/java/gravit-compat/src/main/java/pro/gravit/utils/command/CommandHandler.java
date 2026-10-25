package pro.gravit.utils.command;
import java.util.*;
import ru.neverlauncher.sdk.core.RuntimeCommands;
/** Exposes only commands present in the signed extension CLI manifest. */
public final class CommandHandler {
    private static final ThreadLocal<Object> RESPONSE=new ThreadLocal<>();
    private final RuntimeCommands target;
    /** Optional structured response, emitted by the signed CLI/RPC bridge. */
    public static void respond(Object value){RESPONSE.set(Objects.requireNonNull(value));}
    public CommandHandler(RuntimeCommands target){this.target=Objects.requireNonNull(target);}
    public void registerCommand(String name,Command command){
        Objects.requireNonNull(command);
        target.register(name,null,input->input,raw->{
            if(!(raw instanceof Map<?,?> map)||!(map.get("args") instanceof List<?> list)||list.size()>128)throw new IllegalArgumentException("invalid command input");
            String[] args=new String[list.size()];
            for(int i=0;i<args.length;i++){
                if(!(list.get(i) instanceof String s)||s.length()>8192)throw new IllegalArgumentException("invalid command arg");args[i]=s;
            }
            try{
                command.invoke(args);
                Object result=RESPONSE.get();
                return result==null?Map.of("executed",true,"command",name):result;
            }finally{RESPONSE.remove();}
        });
    }
}
