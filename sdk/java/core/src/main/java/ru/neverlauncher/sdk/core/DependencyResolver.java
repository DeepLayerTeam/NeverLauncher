package ru.launcher.sdk.core;

import java.util.*;

/** Deterministic transitive dependency planning against available versioned manifests (no network or installs). */
public final class DependencyResolver {
    private DependencyResolver() {}
    public static List<ExtensionManifest> resolve(Collection<ExtensionManifest> available, Collection<ExtensionManifest.Dependency> roots) {
        if(available.size()>4096||roots.size()>2048)throw new IllegalArgumentException("dependency graph exceeds size limit");
        Map<String,List<ExtensionManifest>> byId=new HashMap<>();
        for(ExtensionManifest m:available)byId.computeIfAbsent(m.id(),k->new ArrayList<>()).add(m);
        for(List<ExtensionManifest> items:byId.values())items.sort(Comparator.comparing(ExtensionManifest::version).reversed());
        Map<String,ExtensionManifest> selected=search(byId,new LinkedHashMap<>(),new ArrayList<>(roots),0);
        if(selected==null)throw new IllegalArgumentException("no compatible dependency solution");
        List<ExtensionManifest> ordered=new ArrayList<>();Set<String> visited=new HashSet<>(),visiting=new HashSet<>();
        for(String id:selected.keySet())visit(id,selected,visited,visiting,ordered);
        return List.copyOf(ordered);
    }
    private static Map<String,ExtensionManifest> search(Map<String,List<ExtensionManifest>> available,Map<String,ExtensionManifest> selected,List<ExtensionManifest.Dependency> pending,int steps){
        if(steps>10_000||selected.size()>512||pending.size()>8192)throw new IllegalArgumentException("dependency solver complexity limit exceeded");
        if(pending.isEmpty())return selected;
        ExtensionManifest.Dependency next=pending.remove(0);
        ExtensionManifest present=selected.get(next.id());
        if(present!=null){if(!present.version().matches(next.range())&&!next.optional())return null;return search(available,selected,pending,steps+1);}
        List<ExtensionManifest> candidates=available.getOrDefault(next.id(),List.of());
        for(ExtensionManifest candidate:candidates){
            if(!candidate.version().matches(next.range())||!compatible(candidate,selected))continue;
            Map<String,ExtensionManifest> updated=new LinkedHashMap<>(selected);updated.put(next.id(),candidate);
            List<ExtensionManifest.Dependency> queue=new ArrayList<>(candidate.dependencies());queue.addAll(pending);
            Map<String,ExtensionManifest> result=search(available,updated,queue,steps+1);if(result!=null)return result;
        }
        if(next.optional())return search(available,selected,pending,steps+1);
        return null;
    }
    private static boolean compatible(ExtensionManifest candidate,Map<String,ExtensionManifest> selected){
        for(ExtensionManifest other:selected.values()){
            for(ExtensionManifest.Conflict c:candidate.conflicts())if(c.id().equals(other.id())&&other.version().matches(c.range()))return false;
            for(ExtensionManifest.Conflict c:other.conflicts())if(c.id().equals(candidate.id())&&candidate.version().matches(c.range()))return false;
        }return true;
    }
    private static void visit(String id,Map<String,ExtensionManifest> selected,Set<String> visited,Set<String> visiting,List<ExtensionManifest> ordered){
        if(visited.contains(id))return;if(!visiting.add(id))throw new IllegalArgumentException("dependency cycle involving "+id);
        ExtensionManifest m=selected.get(id);
        for(ExtensionManifest.Dependency dep:m.dependencies())if(selected.containsKey(dep.id()))visit(dep.id(),selected,visited,visiting,ordered);
        visiting.remove(id);visited.add(id);ordered.add(m);
    }
}
