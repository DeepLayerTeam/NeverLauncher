package ru.neverlauncher.sdk.gravit;
import pro.gravit.launcher.base.modules.LauncherModule;
import ru.neverlauncher.sdk.core.RuntimeEvents;
@HostEvent(type="project.saved")
public final class ProjectSavedEvent extends LauncherModule.Event {
    public final String id,projectId,idempotencyKey;
    public final Object payload;
    public ProjectSavedEvent(RuntimeEvents.Envelope<Object> source){id=source.id();projectId=source.projectId();idempotencyKey=source.idempotencyKey();payload=source.payload();}
}
