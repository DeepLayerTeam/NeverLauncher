package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class NeverLauncherApiClient {
    private static final String SIGNATURE_SCHEME = "NeverLauncher-ServerBridge-Node-v1";
    private static final List<Integer> SUPPORTED_PROTOCOLS = List.of(BridgeDefaults.PROTOCOL_VERSION, BridgeDefaults.LEGACY_PROTOCOL_VERSION);
    private static final List<String> SUPPORTED_FEATURES = List.of(
        BridgeDefaults.FEATURE_CAPABILITY_NEGOTIATION,
        BridgeDefaults.FEATURE_PROTOCOL_FLAGS,
        BridgeDefaults.FEATURE_ROLLING_UPGRADE,
        BridgeDefaults.FEATURE_NODE_SIGNATURES,
        BridgeDefaults.FEATURE_NONCE_REPLAY,
        BridgeDefaults.FEATURE_ARTIFACT_INTEGRITY,
        BridgeDefaults.FEATURE_ONE_TIME_JOIN,
        BridgeDefaults.FEATURE_ONE_TIME_HANDOFF,
        BridgeDefaults.FEATURE_RUNTIME_TOPOLOGY,
        BridgeDefaults.FEATURE_RUNTIME_DISCOVERY,
        BridgeDefaults.FEATURE_RUNTIME_IDENTITY,
        BridgeDefaults.FEATURE_SERVER_TELEMETRY,
        BridgeDefaults.FEATURE_EVENT_STREAM,
        BridgeDefaults.FEATURE_CONTROL_API,
        BridgeDefaults.FEATURE_ROUTING_V2
    );

    private final BridgeConfig config;
    private final NodeIdentity identity;
    private final HttpClient client;
    private final String serverType;
    private final String pluginVersion;
    private final String pluginSha256;
    private final BridgeRuntimeIdentity runtimeIdentity;
    private final BridgeTelemetrySampler telemetrySampler = new BridgeTelemetrySampler();
    private final AtomicReference<String> routingState = new AtomicReference<>("ready");
    private final BridgeEventJournal eventJournal;
    private final ExecutorService eventExecutor;
    private final AtomicBoolean eventFlushScheduled = new AtomicBoolean(false);
    private final AtomicBoolean eventClosed = new AtomicBoolean(false);
    private final BridgeControlJournal controlJournal;
    private final BridgeControlTrust controlTrust;
    private final AtomicBoolean controlClosed = new AtomicBoolean(false);
    private volatile ScheduledExecutorService controlExecutor;
    private volatile BridgeControlExecutor controlHandler;
    private volatile BridgeProtocolNegotiation negotiation;

    public NeverLauncherApiClient(BridgeConfig config, NodeIdentity identity, String serverType, String pluginVersion, String pluginSha256) {
        this(config, identity, serverType, pluginVersion, pluginSha256,
            BridgeRuntimeDescriptor.of("", serverType, serverType, "", serverType, List.of("heartbeat.signed", "join.validation")));
    }

    public NeverLauncherApiClient(BridgeConfig config, NodeIdentity identity, String serverType, String pluginVersion, String pluginSha256, BridgeRuntimeDescriptor runtimeDescriptor) {
        this.config = config;
        this.identity = identity;
        this.serverType = normalized(serverType);
        this.pluginVersion = normalized(pluginVersion);
        this.pluginSha256 = normalized(pluginSha256).toLowerCase();
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(config.timeoutMs)).build();
        try {
            this.runtimeIdentity = identity == null ? null : BridgeRuntimeIdentity.capture(config, identity, runtimeDescriptor);
            if (this.runtimeIdentity != null && identity != null) {
                this.eventJournal = new BridgeEventJournal(
                    config.identityFile.resolveSibling("event-stream.journal"),
                    config.serverId,
                    this.runtimeIdentity.runtimeId(),
                    identity
                );
                this.eventExecutor = Executors.newSingleThreadExecutor(task -> {
                    Thread thread = new Thread(task, "neverlauncher-serverbridge-event-stream");
                    thread.setDaemon(true);
                    return thread;
                });
                this.controlJournal = new BridgeControlJournal(config.identityFile.resolveSibling("control-channel.journal"));
                this.controlTrust = new BridgeControlTrust(config);
                String crashedRuntime = this.eventJournal.previousUncleanRuntimeId();
                if (!crashedRuntime.isBlank()) {
                    publishEvent("server.crash", Map.of("previousRuntimeId", crashedRuntime, "detectedBy", "journal-recovery"));
                }
            } else {
                this.eventJournal = null;
                this.eventExecutor = null;
                this.controlJournal = null;
                this.controlTrust = null;
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("cannot create ServerBridge runtime identity/event journal", e);
        }
    }

    public boolean heartbeat(String serverType, String pluginVersion) {
        String actualType = first(serverType, this.serverType);
        String actualVersion = first(pluginVersion, this.pluginVersion);
        if (config.requireIntegrity && !BridgeIntegrity.isSha256(pluginSha256)) return false;
        try {
            BridgeProtocolNegotiation protocol = negotiateProtocol();
            String runtime = runtimeFields(protocol);
            String telemetry = telemetryFields(protocol);
            String routing = routingFields(protocol);
            String json = "{" + protocolFields(protocol) +
                ",\"serverId\":" + quote(config.serverId) +
                ",\"serverType\":" + quote(actualType) +
                ",\"pluginVersion\":" + quote(actualVersion) +
                ",\"pluginSha256\":" + quote(pluginSha256) +
                runtime + telemetry + routing + "}";
            HttpRequest request = signedRequest("POST", URI.create(config.heartbeatUrl()), json);
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() >= 200 && response.statusCode() < 300;
        } catch (Exception ignored) {
            return false;
        }
    }

    public JoinValidationResult validateJoin(String username, String uuid, String ip) {
        if (identity == null) {
            return new JoinValidationResult(false, "node_identity_missing", "{}");
        }
        if (config.requireIntegrity && (!BridgeIntegrity.isSha256(pluginSha256) || pluginVersion.isBlank() || serverType.isBlank())) {
            return new JoinValidationResult(false, "bridge_integrity_unavailable", "{}");
        }
        BridgeProtocolNegotiation protocol;
        try {
            protocol = negotiateProtocol();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            return new JoinValidationResult(false, "backend_unavailable", "{}");
        }
        String body = "{" + protocolFields(protocol) + "," +
            "\"serverId\":" + quote(config.serverId) + "," +
            "\"username\":" + quote(username) + "," +
            "\"uuid\":" + quote(uuid) + "," +
            "\"ip\":" + quote(ip) + "," +
            "\"projectId\":" + quote(config.projectId) + "," +
            "\"profileId\":" + quote(config.profileId) + "," +
            "\"channel\":" + quote(config.channel) + "," +
            "\"pluginVersion\":" + quote(pluginVersion) + "," +
            "\"pluginSha256\":" + quote(pluginSha256) +
            "}";
        IOException lastIo = null;
        InterruptedException lastInterrupted = null;
        for (int attempt = 0; attempt <= Math.max(0, config.retries); attempt++) {
            try {
                // A retry is a new authenticated request with a fresh nonce. Reusing
                // a signed request would correctly be rejected as a replay.
                HttpRequest request = signedRequest("POST", URI.create(config.validateJoinUrl()), body);
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String raw = response.body() == null ? "" : response.body();
                boolean allowed = response.statusCode() >= 200 && response.statusCode() < 300 && raw.contains("\"allowed\":true");
                if (allowed) return new JoinValidationResult(true, "session_valid", raw);
                return new JoinValidationResult(false, extractReason(raw), raw);
            } catch (IOException e) {
                lastIo = e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                lastInterrupted = e;
                break;
            } catch (GeneralSecurityException e) {
                return new JoinValidationResult(false, "node_identity_signing_failed", "{}");
            }
        }
        String reason = lastInterrupted != null ? "backend_interrupted" : (lastIo != null ? "backend_unavailable" : "backend_denied");
        boolean failOpen = "open".equalsIgnoreCase(config.failMode) && !config.requireLauncherSession && !config.requireIntegrity;
        return new JoinValidationResult(failOpen, reason, "{}");
    }

    public JoinValidationResult createHandoff(String username, String targetServer) {
        if (identity == null) return new JoinValidationResult(false, "node_identity_missing", "{}");
        BridgeProtocolNegotiation protocol;
        try {
            protocol = negotiateProtocol();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            return new JoinValidationResult(false, "backend_unavailable", "{}");
        }
        if (protocol.protocolVersion() >= BridgeDefaults.PROTOCOL_VERSION && protocol.features().contains(BridgeDefaults.FEATURE_ROUTING_V2)) {
            JoinValidationResult route = verifyTargetRoute(targetServer);
            if (!route.allowed) return route;
        }
        String body = "{" + protocolFields(protocol) + "," +
            "\"username\":" + quote(username) + "," +
            "\"targetServer\":" + quote(targetServer) +
            "}";
        IOException lastIo = null;
        for (int attempt = 0; attempt <= Math.max(0, config.retries); attempt++) {
            try {
                HttpRequest request = signedRequest("POST", URI.create(config.handoffUrl()), body);
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                String raw = response.body() == null ? "" : response.body();
                if (response.statusCode() >= 200 && response.statusCode() < 300 && raw.contains("\"status\":\"handoff-created\"")) {
                    return new JoinValidationResult(true, "handoff_created", raw);
                }
                return new JoinValidationResult(false, extractReason(raw), raw);
            } catch (IOException e) {
                lastIo = e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new JoinValidationResult(false, "backend_interrupted", "{}");
            } catch (GeneralSecurityException e) {
                return new JoinValidationResult(false, "node_identity_signing_failed", "{}");
            }
        }
        return new JoinValidationResult(false, lastIo == null ? "backend_denied" : "backend_unavailable", "{}");
    }

    public int negotiatedProtocolVersion() {
        BridgeProtocolNegotiation current = negotiation;
        return current == null ? 0 : current.protocolVersion();
    }

    private BridgeProtocolNegotiation negotiateProtocol() throws IOException, InterruptedException {
        BridgeProtocolNegotiation current = negotiation;
        Instant now = Instant.now();
        if (current != null && !current.expired(now)) return current;
        synchronized (this) {
            current = negotiation;
            now = Instant.now();
            if (current != null && !current.expired(now)) return current;

            String protocols = SUPPORTED_PROTOCOLS.stream().map(String::valueOf).reduce((a, b) -> a + "," + b).orElse("3,2");
            String features = String.join(",", SUPPORTED_FEATURES);
            String query = "protocols=" + URLEncoder.encode(protocols, StandardCharsets.UTF_8) +
                "&features=" + URLEncoder.encode(features, StandardCharsets.UTF_8);
            URI uri = URI.create(config.capabilitiesUrl() + "?" + query);
            HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofMillis(config.timeoutMs))
                .header("Accept", "application/json")
                .GET()
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // 0.19.0 and older backends do not expose capabilities. A 404 is the
            // deliberate rolling-upgrade signal; other failures do not silently
            // downgrade an otherwise v3-capable deployment.
            if (response.statusCode() == 404) {
                current = new BridgeProtocolNegotiation(BridgeDefaults.LEGACY_PROTOCOL_VERSION, List.of(), true, now);
                negotiation = current;
                return current;
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("ServerBridge capability negotiation failed with HTTP " + response.statusCode());
            }
            String raw = response.body() == null ? "" : response.body();
            int selected = extractJsonInt(raw, "negotiatedProtocolVersion");
            List<String> enabled = extractJsonStringArray(raw, "features");
            if (!SUPPORTED_PROTOCOLS.contains(selected)) {
                throw new IOException("Backend selected unsupported ServerBridge protocol " + selected);
            }
            if (selected == BridgeDefaults.PROTOCOL_VERSION &&
                (!enabled.contains(BridgeDefaults.FEATURE_CAPABILITY_NEGOTIATION) || !enabled.contains(BridgeDefaults.FEATURE_PROTOCOL_FLAGS))) {
                throw new IOException("Backend selected Protocol v3 without required feature flags");
            }
            current = new BridgeProtocolNegotiation(selected, enabled, false, now);
            negotiation = current;
            return current;
        }
    }


    private String runtimeFields(BridgeProtocolNegotiation protocol) {
        if (protocol.protocolVersion() < BridgeDefaults.PROTOCOL_VERSION || runtimeIdentity == null) return "";
        boolean discovery = protocol.features().contains(BridgeDefaults.FEATURE_RUNTIME_DISCOVERY);
        boolean identityFeature = protocol.features().contains(BridgeDefaults.FEATURE_RUNTIME_IDENTITY);
        if (!discovery && !identityFeature) return "";
        if (!(discovery && identityFeature)) {
            throw new IllegalStateException("ServerBridge runtime discovery requires the runtime identity feature pair");
        }
        return ",\"runtime\":" + runtimeIdentity.toJson();
    }

    public String runtimeId() {
        return runtimeIdentity == null ? "" : runtimeIdentity.runtimeId();
    }


    public void recordPlatformTelemetry(BridgePlatformTelemetry sample) {
        telemetrySampler.recordPlatformSample(sample);
    }

    public void setRoutingModes(boolean maintenance, boolean draining) {
        routingState.set(maintenance ? "maintenance" : (draining ? "draining" : "ready"));
    }

    private String routingFields(BridgeProtocolNegotiation protocol) throws GeneralSecurityException {
        if (protocol.protocolVersion() < BridgeDefaults.PROTOCOL_VERSION || runtimeIdentity == null || identity == null) return "";
        if (!protocol.features().contains(BridgeDefaults.FEATURE_ROUTING_V2)) return "";
        BridgePlatformTelemetry sample = telemetrySampler.latestPlatformSample();
        int online = sample == null ? 0 : sample.playersOnline();
        int capacity = sample == null ? 0 : sample.playersMax();
        String health = routingHealth(sample);
        BridgeRoutingSnapshot routing = BridgeRoutingSnapshot.create(
            config.serverId, runtimeIdentity.runtimeId(), routingState.get(), online, capacity, health, identity
        );
        return ",\"routing\":" + routing.toJson();
    }

    private static String routingHealth(BridgePlatformTelemetry sample) {
        if (sample == null) return "unhealthy";
        Double mspt = sample.mspt();
        Double tps = sample.tps();
        if ((mspt != null && mspt >= 50.0d) || (tps != null && tps < 15.0d)) return "unhealthy";
        if ((mspt != null && mspt >= 40.0d) || (tps != null && tps < 19.0d)) return "degraded";
        return "healthy";
    }

    private JoinValidationResult verifyTargetRoute(String targetServer) {
        try {
            HttpRequest request = signedRequest("GET", URI.create(config.routesUrl()), "");
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return new JoinValidationResult(false, "routing_table_unavailable", response.body() == null ? "{}" : response.body());
            }
            String raw = response.body() == null ? "" : response.body();
            String target = targetServer == null ? "" : targetServer.trim();
            String quoted = quote(target);
            boolean present = raw.contains("\"nodeId\":" + quoted) || raw.contains("\"backendName\":" + quoted);
            return new JoinValidationResult(present, present ? "route_allowed" : "target_not_routable", raw);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new JoinValidationResult(false, "backend_interrupted", "{}");
        } catch (IOException | GeneralSecurityException e) {
            return new JoinValidationResult(false, "routing_table_unavailable", "{}");
        }
    }

    /** Enqueue an individually signed event without blocking the game/proxy thread on HTTP. */
    public boolean publishEvent(String type, Map<String, String> payload) {
        BridgeEventJournal journal = eventJournal;
        if (journal == null || eventClosed.get()) return false;
        try {
            journal.append(type, payload == null ? Map.of() : payload);
            scheduleEventFlush();
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    public void flushEventsNow() {
        if (eventJournal == null || eventClosed.get()) return;
        flushEventStream();
    }

    /** Start the authenticated Backend -> Bridge control worker. Execution is serialized and at-most-once per command journal. */
    public synchronized void startControlChannel(BridgeControlExecutor executor) {
        if (executor == null) throw new IllegalArgumentException("control executor is required");
        if (runtimeIdentity == null || identity == null || controlJournal == null || controlTrust == null) return;
        this.controlHandler = executor;
        if (controlExecutor != null && !controlExecutor.isShutdown()) return;
        controlClosed.set(false);
        controlExecutor = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "neverlauncher-serverbridge-control");
            thread.setDaemon(true);
            return thread;
        });
        controlExecutor.scheduleWithFixedDelay(this::pollControlSafely, 0L, Math.max(1, config.controlPollIntervalSeconds), TimeUnit.SECONDS);
    }

    public synchronized void closeControlChannel() {
        if (!controlClosed.compareAndSet(false, true)) return;
        ScheduledExecutorService executor = controlExecutor;
        controlExecutor = null;
        if (executor != null) {
            executor.shutdownNow();
            try { executor.awaitTermination(1500, TimeUnit.MILLISECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    private void pollControlSafely() {
        if (controlClosed.get()) return;
        try { pollControlOnce(); } catch (Exception ignored) { /* heartbeat/events surface backend health; control retries next interval */ }
    }

    private void pollControlOnce() throws Exception {
        BridgeProtocolNegotiation protocol = negotiateProtocol();
        if (protocol.protocolVersion() < BridgeDefaults.PROTOCOL_VERSION || !protocol.features().contains(BridgeDefaults.FEATURE_CONTROL_API)) return;
        BridgeControlExecutor executor = controlHandler;
        if (executor == null) return;
        URI uri = URI.create(config.controlPollUrl() + "?runtimeId=" + URLEncoder.encode(runtimeIdentity.runtimeId(), StandardCharsets.UTF_8));
        HttpResponse<String> response = client.send(signedRequest("GET", uri, ""), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 204) return;
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            if (response.statusCode() >= 500) return;
            throw new IOException("control poll rejected with HTTP " + response.statusCode());
        }
        String raw = response.body() == null ? "" : response.body();
        String serverId = extractJsonString(raw, "serverId");
        String commandId = extractJsonString(raw, "commandId");
        String runtimeId = extractJsonString(raw, "runtimeId");
        long runtimeEpoch = extractJsonLong(raw, "runtimeEpoch");
        String type = extractJsonString(raw, "type");
        String payloadEncoded = extractJsonString(raw, "payload");
        String payloadSha256 = extractJsonString(raw, "payloadSha256");
        int attempt = extractJsonInt(raw, "attempt");
        long issuedAt = extractJsonLong(raw, "issuedAtUnixMillis");
        long expiresAt = extractJsonLong(raw, "expiresAtUnixMillis");
        String signingPublicKey = extractJsonString(raw, "signingPublicKey");
        String signature = extractJsonString(raw, "signature");
        if (!config.serverId.equals(serverId) || !runtimeIdentity.runtimeId().equalsIgnoreCase(runtimeId) || commandId.isBlank() || type.isBlank()) {
            throw new IOException("control command binding mismatch");
        }
        long now = System.currentTimeMillis();
        if (issuedAt <= 0 || expiresAt <= now || issuedAt > now + 120_000L || expiresAt - issuedAt > 660_000L) {
            throw new IOException("control command outside accepted time window");
        }
        byte[] payloadRaw = payloadEncoded.isBlank() ? "{}".getBytes(StandardCharsets.UTF_8) : Base64.getUrlDecoder().decode(payloadEncoded);
        if (payloadRaw.length > 4096) throw new IOException("control payload too large");
        String actualPayloadHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payloadRaw));
        if (!MessageDigest.isEqual(actualPayloadHash.getBytes(StandardCharsets.US_ASCII), payloadSha256.toLowerCase().getBytes(StandardCharsets.US_ASCII))) {
            throw new GeneralSecurityException("control payload digest mismatch");
        }
        Map<String,String> payload = BridgeControlCommand.decodePayload(payloadEncoded);
        BridgeControlCommand command = new BridgeControlCommand(serverId, commandId, runtimeId, runtimeEpoch, type, payload, payloadSha256, attempt, issuedAt, expiresAt, signingPublicKey, signature);
        if (!controlTrust.verify(command)) throw new GeneralSecurityException("control command signature or backend trust failed");

        BridgeControlJournal.State state = controlJournal.state(command);
        BridgeControlResult result;
        if (state == null) {
            controlJournal.begin(command);
            try { result = executor.execute(command); }
            catch (Exception e) { result = BridgeControlResult.failed(e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage())); }
            if (result == null) result = BridgeControlResult.failed("platform executor returned no result");
            controlJournal.complete(command, result);
        } else if ("executing".equals(state.phase())) {
            result = BridgeControlResult.indeterminate("previous bridge process/reload stopped after execution began; command was not re-executed");
            controlJournal.complete(command, result);
        } else {
            result = state.result();
            if (result == null) result = BridgeControlResult.indeterminate("control journal result unavailable");
        }
        sendControlAck(command, result);
    }

    private void sendControlAck(BridgeControlCommand command, BridgeControlResult result) throws Exception {
        String body = "{" + protocolFields(negotiateProtocol()) +
            ",\"serverId\":" + quote(config.serverId) +
            ",\"runtimeId\":" + quote(runtimeIdentity.runtimeId()) +
            ",\"commandId\":" + quote(command.commandId()) +
            ",\"status\":" + quote(result.status()) +
            ",\"result\":" + quote(BridgeControlCommand.encodeMap(result.result())) +
            ",\"error\":" + quote(result.error()) + "}";
        HttpResponse<String> response = client.send(signedRequest("POST", URI.create(config.controlAckUrl()), body), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) throw new IOException("control ACK rejected with HTTP " + response.statusCode());
    }

    /** Best-effort final flush; the journal remains authoritative if the backend is unavailable. */
    public void closeEventStreamCleanly() {
        closeControlChannel();
        if (!eventClosed.compareAndSet(false, true)) return;
        try { flushEventStream(); } catch (RuntimeException ignored) {}
        try { if (eventJournal != null) eventJournal.markClean(); } catch (IOException ignored) {}
        if (eventExecutor != null) {
            eventExecutor.shutdown();
            try { eventExecutor.awaitTermination(1500, TimeUnit.MILLISECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    private void scheduleEventFlush() {
        ExecutorService executor = eventExecutor;
        if (executor == null || executor.isShutdown() || eventClosed.get()) return;
        if (!eventFlushScheduled.compareAndSet(false, true)) return;
        executor.execute(() -> {
            try { flushEventStream(); }
            finally { eventFlushScheduled.set(false); }
        });
    }

    private void flushEventStream() {
        BridgeEventJournal journal = eventJournal;
        if (journal == null) return;
        for (int drain = 0; drain < 4; drain++) {
            List<BridgeEventRecord> batch = journal.nextBatch(64);
            if (batch.isEmpty()) return;
            long ack;
            try {
                ack = sendEventBatch(batch);
            } catch (Exception ignored) {
                return;
            }
            if (ack < batch.get(0).sequence()) return;
            try { journal.acknowledge(ack); } catch (IOException ignored) { return; }
            if (ack < batch.get(batch.size() - 1).sequence()) return;
        }
    }

    private long sendEventBatch(List<BridgeEventRecord> batch) throws IOException, InterruptedException, GeneralSecurityException {
        BridgeProtocolNegotiation protocol = negotiateProtocol();
        if (protocol.protocolVersion() < BridgeDefaults.PROTOCOL_VERSION || !protocol.features().contains(BridgeDefaults.FEATURE_EVENT_STREAM)) {
            return batch.get(batch.size() - 1).sequence(); // rolling-upgrade backend: bounded local queue, feature unavailable
        }
        StringBuilder events = new StringBuilder("[");
        for (int i = 0; i < batch.size(); i++) {
            if (i > 0) events.append(',');
            events.append(batch.get(i).toJson());
        }
        events.append(']');
        String body = "{" + protocolFields(protocol) +
            ",\"serverId\":" + quote(config.serverId) +
            ",\"runtimeId\":" + quote(runtimeIdentity.runtimeId()) +
            ",\"events\":" + events + "}";
        IOException last = null;
        for (int attempt = 0; attempt <= Math.max(0, config.retries); attempt++) {
            try {
                HttpRequest request = signedRequest("POST", URI.create(config.eventStreamUrl()), body);
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    if (response.statusCode() >= 500) { last = new IOException("event stream backend HTTP " + response.statusCode()); continue; }
                    throw new IOException("event stream rejected with HTTP " + response.statusCode());
                }
                long ack = extractJsonLong(response.body() == null ? "" : response.body(), "ackSequence");
                if (ack < 0) throw new IOException("event stream response missing ACK");
                return ack;
            } catch (IOException e) {
                last = e;
            }
        }
        throw last == null ? new IOException("event stream delivery failed") : last;
    }

    private String telemetryFields(BridgeProtocolNegotiation protocol) {
        if (protocol.protocolVersion() < BridgeDefaults.PROTOCOL_VERSION || runtimeIdentity == null) return "";
        if (!protocol.features().contains(BridgeDefaults.FEATURE_SERVER_TELEMETRY)) return "";
        BridgeTelemetrySnapshot snapshot = telemetrySampler.sample(runtimeIdentity.runtimeId());
        return ",\"telemetry\":" + snapshot.toJson();
    }

    private static String protocolFields(BridgeProtocolNegotiation protocol) {
        String base = "\"protocolVersion\":" + protocol.protocolVersion();
        if (protocol.protocolVersion() < BridgeDefaults.PROTOCOL_VERSION) return base;
        return base + ",\"features\":" + jsonArray(protocol.features());
    }

    private HttpRequest signedRequest(String method, URI uri, String body) throws GeneralSecurityException {
        String timestamp = Long.toString(Instant.now().getEpochSecond());
        String nonce = identity.newNonce();
        String canonical = canonicalRequest(method, uri, body, timestamp, nonce);
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(identity.sign(canonical));
        return HttpRequest.newBuilder(uri)
            .timeout(Duration.ofMillis(config.timeoutMs))
            .header("Content-Type", "application/json")
            .header("X-NeverLauncher-Node-Id", config.serverId)
            .header("X-NeverLauncher-Node-Key-Fingerprint", identity.fingerprint())
            .header("X-NeverLauncher-Node-Timestamp", timestamp)
            .header("X-NeverLauncher-Node-Nonce", nonce)
            .header("X-NeverLauncher-Node-Signature", signature)
            .method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
    }

    private String canonicalRequest(String method, URI uri, String body, String timestamp, String nonce) throws GeneralSecurityException {
        String target = uri.getRawPath();
        if (target == null || target.isEmpty()) target = "/";
        if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty()) target += "?" + uri.getRawQuery();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.UTF_8));
        return String.join("\n",
            SIGNATURE_SCHEME,
            config.serverId.trim(),
            method.toUpperCase(),
            target,
            timestamp,
            nonce,
            HexFormat.of().formatHex(digest)
        );
    }

    private static String quote(String value) {
        if (value == null) value = "";
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('"').toString();
    }

    private static String jsonArray(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) out.append(',');
            out.append(quote(values.get(i)));
        }
        return out.append(']').toString();
    }

    private static String extractReason(String raw) {
        String reason = extractJsonString(raw, "reason");
        if (!reason.isBlank()) return reason;
        String message = extractJsonString(raw, "message");
        return message.isBlank() ? "session_denied" : message;
    }

    private static long extractJsonLong(String raw, String field) {
        String marker = "\"" + field + "\":";
        int idx = raw.indexOf(marker);
        if (idx < 0) return -1L;
        int start = idx + marker.length();
        while (start < raw.length() && Character.isWhitespace(raw.charAt(start))) start++;
        int end = start;
        while (end < raw.length() && Character.isDigit(raw.charAt(end))) end++;
        if (end == start) return -1L;
        try { return Long.parseLong(raw.substring(start, end)); } catch (NumberFormatException ignored) { return -1L; }
    }

    private static int extractJsonInt(String raw, String field) {
        String marker = "\"" + field + "\":";
        int idx = raw.indexOf(marker);
        if (idx < 0) return 0;
        int start = idx + marker.length();
        while (start < raw.length() && Character.isWhitespace(raw.charAt(start))) start++;
        int end = start;
        while (end < raw.length() && Character.isDigit(raw.charAt(end))) end++;
        if (end == start) return 0;
        try { return Integer.parseInt(raw.substring(start, end)); } catch (NumberFormatException ignored) { return 0; }
    }

    private static List<String> extractJsonStringArray(String raw, String field) {
        String marker = "\"" + field + "\":";
        int idx = raw.indexOf(marker);
        if (idx < 0) return List.of();
        int start = raw.indexOf('[', idx + marker.length());
        int end = start < 0 ? -1 : raw.indexOf(']', start + 1);
        if (start < 0 || end < 0) return List.of();
        String body = raw.substring(start + 1, end).trim();
        if (body.isEmpty()) return List.of();
        List<String> out = new ArrayList<>();
        for (String item : body.split(",")) {
            String value = item.trim();
            if (value.length() >= 2 && value.charAt(0) == '"' && value.charAt(value.length() - 1) == '"') {
                value = value.substring(1, value.length() - 1);
            }
            if (!value.isBlank()) out.add(value);
        }
        return List.copyOf(out);
    }

    private static String extractJsonString(String raw, String field) {
        String marker = "\"" + field + "\":";
        int idx = raw.indexOf(marker);
        if (idx < 0) return "";
        int start = raw.indexOf('"', idx + marker.length());
        int end = start >= 0 ? raw.indexOf('"', start + 1) : -1;
        if (start >= 0 && end > start) return raw.substring(start + 1, end);
        return "";
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim();
    }

    private static String first(String preferred, String fallback) {
        String value = normalized(preferred);
        return value.isBlank() ? normalized(fallback) : value;
    }
}
