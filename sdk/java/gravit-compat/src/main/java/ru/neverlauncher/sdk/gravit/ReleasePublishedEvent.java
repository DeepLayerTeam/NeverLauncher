package ru.launcher.sdk.gravit;
import pro.gravit.launcher.base.modules.LauncherModule;
import ru.launcher.sdk.core.RuntimeEvents;
import java.util.Map;
/** Go eventbus release.published with original idempotency metadata. */
@HostEvent(type="release.published")
public final class ReleasePublishedEvent extends LauncherModule.Event {
    public final String id,projectId,idempotencyKey;
    public final Object payload;
    public ReleasePublishedEvent(RuntimeEvents.Envelope<Object> source){
        id=source.id();projectId=source.projectId();idempotencyKey=source.idempotencyKey();payload=source.payload();
    }
}
