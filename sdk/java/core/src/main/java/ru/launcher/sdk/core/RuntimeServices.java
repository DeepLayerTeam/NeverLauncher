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
    private final IdentityServices identity = new IdentityServices();
    public RuntimeServices(HostSession host,Set<String> declaredCommands){
        this.host=Objects.requireNonNull(host);config=new RuntimeDocuments(host,"config");storage=new RuntimeDocuments(host,"storage");
        secrets=new Secrets(host);events=new RuntimeEvents(host);commands=new RuntimeCommands(declaredCommands);backend=new BackendServices(host);
    }
    public RuntimeDocuments config(){return config;}
    public RuntimeDocuments storage(){return storage;}
    public Secrets secrets(){return secrets;}
    public RuntimeEvents events(){return events;}
    public RuntimeCommands commands(){return commands;}
    public BackendServices backend(){return backend;}
    public IdentityServices identity(){return identity;}
    @Override public void close(){events.close();}
}
