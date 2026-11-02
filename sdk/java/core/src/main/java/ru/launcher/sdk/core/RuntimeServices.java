package ru.launcher.sdk.core;

import java.util.*;

/** Live runtime services backed by the Go host broker, not a mock or local client-side cache. */
public final class RuntimeServices implements AutoCloseable {
    private final HostSession host;
    private final RuntimeDocuments config,storage;
    private final Secrets secrets;
    private final RuntimeEvents events;
    private final RuntimeCommands commands;
    private final BackendServices backend;
    private final ServerBridgeServices serverBridge;
    private final IdentityServices identity = new IdentityServices();
    private final ContentServices content;
    private final RuntimeUI ui;
    public RuntimeServices(HostSession host,Set<String> declaredCommands){this(host,declaredCommands,Map.of());}
    public RuntimeServices(HostSession host,Set<String> declaredCommands,Map<String,Set<String>> uiActions){
        this.host=Objects.requireNonNull(host);config=new RuntimeDocuments(host,"config");storage=new RuntimeDocuments(host,"storage");
        secrets=new Secrets(host);events=new RuntimeEvents(host);commands=new RuntimeCommands(declaredCommands);backend=new BackendServices(host);serverBridge=new ServerBridgeServices(host,events);content=new ContentServices(host);ui=new RuntimeUI(config,uiActions);
    }
    public RuntimeDocuments config(){return config;}
    public RuntimeDocuments storage(){return storage;}
    public Secrets secrets(){return secrets;}
    public RuntimeEvents events(){return events;}
    public RuntimeCommands commands(){return commands;}
    public BackendServices backend(){return backend;}
    public ServerBridgeServices serverBridge(){return serverBridge;}
    public IdentityServices identity(){return identity;}
    public ContentServices content(){return content;}
    public RuntimeUI ui(){return ui;}
    @Override public void close(){ui.close();events.close();}
}
