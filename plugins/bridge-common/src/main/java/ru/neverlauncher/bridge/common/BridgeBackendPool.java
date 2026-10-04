package ru.neverlauncher.bridge.common;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLongArray;

final class BridgeBackendPool {
    record Endpoint(int index, String baseUrl, URI uri) {}

    private final List<String> bases;
    private final AtomicInteger active = new AtomicInteger(0);
    private final AtomicLongArray blockedUntilMillis;
    private final long cooldownMillis;

    BridgeBackendPool(List<String> bases, long cooldownMillis) {
        if (bases == null || bases.isEmpty()) throw new IllegalArgumentException("at least one backend endpoint is required");
        this.bases = List.copyOf(bases);
        this.blockedUntilMillis = new AtomicLongArray(this.bases.size());
        this.cooldownMillis = Math.max(250L, cooldownMillis);
    }

    List<Endpoint> candidates(String relative) {
        if (relative == null || relative.isBlank() || relative.charAt(0) != '/') throw new IllegalArgumentException("backend relative path must start with /");
        int start = Math.floorMod(active.get(), bases.size());
        long now = System.currentTimeMillis();
        List<Endpoint> healthy = new ArrayList<>(bases.size());
        List<Endpoint> blocked = new ArrayList<>(bases.size());
        for (int offset = 0; offset < bases.size(); offset++) {
            int i = (start + offset) % bases.size();
            Endpoint endpoint = new Endpoint(i, bases.get(i), URI.create(bases.get(i) + relative));
            if (blockedUntilMillis.get(i) <= now) healthy.add(endpoint); else blocked.add(endpoint);
        }
        healthy.addAll(blocked); // all-down case still probes every configured endpoint once
        return healthy;
    }

    void success(int index) {
        blockedUntilMillis.set(index, 0L);
        active.set(index);
    }

    void failure(int index) {
        blockedUntilMillis.set(index, System.currentTimeMillis() + cooldownMillis);
        if (active.get() == index && bases.size() > 1) active.compareAndSet(index, (index + 1) % bases.size());
    }

    int size() { return bases.size(); }
    String activeBaseUrl() { return bases.get(Math.floorMod(active.get(), bases.size())); }
}
