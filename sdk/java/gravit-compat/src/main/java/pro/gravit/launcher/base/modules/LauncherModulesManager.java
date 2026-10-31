package pro.gravit.launcher.base.modules;
import java.lang.reflect.Constructor;
import java.util.*;
import pro.gravit.utils.command.CommandHandler;
import ru.launcher.sdk.core.RuntimeEvents;
import ru.launcher.sdk.core.RuntimeServices;
import ru.launcher.sdk.gravit.HostEvent;

/** Explicitly maps ported module event handlers to real Go EventBus subscriptions. */
public final class LauncherModulesManager {
    private record Registration<T extends LauncherModule.Event>(Class<T> type,LauncherModule.EventHandler<T> callback) {}
    private final RuntimeServices runtime;
    private final Map<String,List<Registration<?>>> pending=new LinkedHashMap<>();
    private boolean active;
    public final CommandHandler commandHandler;
    public LauncherModulesManager(RuntimeServices runtime){this.runtime=Objects.requireNonNull(runtime);commandHandler=new CommandHandler(runtime.commands());}
    public CommandHandler getCommandHandler(){return commandHandler;}
    public synchronized <T extends LauncherModule.Event> boolean registerEvent(Class<T> type,LauncherModule.EventHandler<T> callback){
        if(active)throw new IllegalStateException("event registration is closed after module init");
        Objects.requireNonNull(callback);
        HostEvent annotation=type.getAnnotation(HostEvent.class);
        if(annotation==null)throw new UnsupportedOperationException("Gravit event is not mapped to Extensions: "+type.getName());
        if(!annotation.type().matches("[a-z][a-z0-9.-]{1,127}")||!Set.of("async","sync").contains(annotation.mode()))throw new IllegalArgumentException("invalid host event mapping");
        try{type.getConstructor(RuntimeEvents.Envelope.class);}catch(NoSuchMethodException e){throw new IllegalArgumentException("ported event missing envelope constructor",e);}
        pending.computeIfAbsent(annotation.type()+":"+annotation.mode(),x->new ArrayList<>()).add(new Registration<>(type,callback));
        return true;
    }
    /** Subscribe only after successful init, never during a partially initialized Gravit module. */
    public synchronized void activate() throws Exception {
        if(active)throw new IllegalStateException("already activated");
        for(var item:pending.entrySet()){
            int i=item.getKey().lastIndexOf(':');
            String eventType=item.getKey().substring(0,i),mode=item.getKey().substring(i+1);
            var registrations=List.copyOf(item.getValue());
            runtime.events().subscribe(eventType,mode,null,value->value,event->{
                for(Registration<?> registration:registrations)invoke(registration,event);
            });
        }
        active=true;pending.clear();
    }
    private static <T extends LauncherModule.Event> void invoke(Registration<T> registration,RuntimeEvents.Envelope<Object> envelope)throws Exception {
        Constructor<T> constructor=registration.type().getConstructor(RuntimeEvents.Envelope.class);
        registration.callback().event(constructor.newInstance(envelope));
    }
}
