package ru.launcher.bridge.common;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Fail-closed interpretation of Backend join and handoff results. A substring
 * such as {"error":{"allowed":true}} must never authorize a Minecraft login.
 * No third-party JSON dependency is required by the platform-neutral bridge.
 */
public final class BridgeAuthResponse0287 {
    private BridgeAuthResponse0287() {}

    public record Decision(boolean allowed, String reason, String correlation, String uuid) {
        static Decision deny(String reason) { return new Decision(false, reason, "", ""); }
    }

    public static Decision join(int httpStatus, String body, String nodeId, String username, String observedUUID) {
        try {
            Map<String, Object> root = Json.parse(body);
            Map<String, Object> data = object(root.get("data"));
            if (httpStatus < 200 || httpStatus >= 300 || !Boolean.TRUE.equals(data.get("allowed")))
                return Decision.deny(safeReason(text(data, "reason"), "backend_join_denied"));
            if (!nodeId.equals(text(data, "serverId")) || !username.equalsIgnoreCase(text(data, "username")))
                return Decision.deny("join_response_identity_mismatch");
            String mode = text(data, "authorization");
            if (!"direct-ticket".equals(mode) && !"proxy-handoff".equals(mode))
                return Decision.deny("join_authorization_missing");
            Map<String, Object> player = object(data.get("player"));
            String uuid = canonicalUUID(text(player, "uuid"));
            if (uuid.isEmpty()) return Decision.deny("join_authorized_uuid_invalid");
            if (observedUUID != null && !observedUUID.isBlank() && !uuid.equals(canonicalUUID(observedUUID)))
                return Decision.deny("join_player_uuid_mismatch");
            String correlation = text(data, "sessionCorrelationId").toLowerCase(Locale.ROOT);
            if (!hex64(correlation)) return Decision.deny("join_correlation_missing");
            return new Decision(true, "session_valid", correlation, uuid);
        } catch (IllegalArgumentException e) {
            return Decision.deny("join_response_invalid");
        }
    }

    public static Decision handoff(int httpStatus, String body, String nodeId, String username,
                                   String target, String correlation) {
        if (httpStatus < 200 || httpStatus >= 300) return Decision.deny("backend_handoff_denied");
        try {
            Map<String, Object> root = Json.parse(body);
            Map<String, Object> data = object(root.get("data"));
            if (!"handoff-created".equals(text(data, "status")) ||
                !nodeId.equals(text(data, "sourceNodeId")) ||
                !username.equalsIgnoreCase(text(data, "username")) ||
                !(target.equalsIgnoreCase(text(data, "targetNodeId")) || target.equalsIgnoreCase(text(data, "backendName"))))
                return Decision.deny("handoff_response_identity_mismatch");
            if (!hex64(correlation) || !correlation.equalsIgnoreCase(text(data, "sessionCorrelationId")))
                return Decision.deny("handoff_correlation_mismatch");
            if (!text(data, "handoffId").matches("ho_[A-Za-z0-9_-]{32}"))
                return Decision.deny("handoff_id_invalid");
            Instant expiry = Instant.parse(text(data, "expiresAt"));
            Instant now = Instant.now();
            if (!expiry.isAfter(now) || expiry.isAfter(now.plusSeconds(60)))
                return Decision.deny("handoff_expired_or_invalid");
            return new Decision(true, "handoff_created", correlation, "");
        } catch (IllegalArgumentException | DateTimeParseException e) {
            return Decision.deny("handoff_response_invalid");
        }
    }

    /** Evaluate the authenticated Backend route-list response, never JSON substrings.
     * A route is valid for the current source, target and live runtime only.
     * The Backend remains authoritative when the one-time handoff is created.
     */
    public static Decision route(int httpStatus, String body, String sourceNodeId, String requestedTarget,
                                 Instant now) {
        if (httpStatus < 200 || httpStatus >= 300) return Decision.deny("routing_table_unavailable");
        if (sourceNodeId == null || sourceNodeId.isBlank() || requestedTarget == null || requestedTarget.isBlank())
            return Decision.deny("invalid_route_request");
        try {
            Map<String, Object> data = object(Json.parse(body).get("data"));
            if (!sourceNodeId.equals(text(data, "sourceNodeId")))
                return Decision.deny("routing_source_mismatch");
            Object rawItems = data.get("items");
            if (!(rawItems instanceof List<?> items) || items.size() > 4096)
                return Decision.deny("routing_table_invalid");
            long freshness = wholeNumber(data.get("freshnessSeconds"));
            if (freshness < 1 || freshness > 90) return Decision.deny("routing_freshness_invalid");
            String target = requestedTarget.trim();
            int matches = 0;
            boolean healthy = false;
            for (Object raw : items) {
                Map<String, Object> item = object(raw);
                String node = text(item, "nodeId");
                String backend = text(item, "backendName");
                if (!target.equalsIgnoreCase(node) && !target.equalsIgnoreCase(backend)) continue;
                matches++;
                if (matches > 1) return Decision.deny("ambiguous_route");
                String runtimeId = text(item, "runtimeId");
                String digest = text(item, "routingDigest");
                if (!hex64(runtimeId.toLowerCase(Locale.ROOT)) || !hex64(digest.toLowerCase(Locale.ROOT)) ||
                    wholeNumber(item.get("runtimeEpoch")) < 1 ||
                    wholeNumber(item.get("routingRevision")) < 1) return Decision.deny("route_runtime_invalid");
                long capacity = wholeNumber(item.get("capacityMax"));
                long online = wholeNumber(item.get("playersOnline"));
                long slots = wholeNumber(item.get("availableSlots"));
                if (capacity < 0 || online < 0 || slots < 0 ||
                    (capacity > 0 && (online >= capacity || slots <= 0)))
                    return Decision.deny("target_capacity_unavailable");
                Instant observed = Instant.parse(text(item, "observedAt"));
                Instant heartbeat = Instant.parse(text(item, "lastHeartbeatAt"));
                // At most 5 seconds of clock skew. No stale targets accepted even if
                // an upstream replica returns a cached route after topology changes.
                if (observed.isAfter(now.plusSeconds(5)) || heartbeat.isAfter(now.plusSeconds(5)) ||
                    observed.isBefore(now.minusSeconds(freshness)) ||
                    heartbeat.isBefore(now.minusSeconds(freshness)))
                    return Decision.deny("target_route_stale");
                healthy = "ready".equals(text(item, "state")) &&
                    ("healthy".equals(text(item, "health")) || "degraded".equals(text(item, "health")));
                if (!healthy) return Decision.deny("target_not_routable");
            }
            return matches == 1 && healthy
                ? new Decision(true, "route_allowed", "", "")
                : Decision.deny("target_not_routable");
        } catch (IllegalArgumentException | DateTimeParseException | ClassCastException e) {
            return Decision.deny("routing_table_invalid");
        }
    }

    private static long wholeNumber(Object value) {
        if (!(value instanceof Number number)) throw new IllegalArgumentException("integer missing");
        double d = number.doubleValue();
        if (!Double.isFinite(d) || d != Math.rint(d) || d > Long.MAX_VALUE || d < Long.MIN_VALUE)
            throw new IllegalArgumentException("invalid integer");
        return (long) d;
    }

    public static boolean matchesAuthenticatedUUID(String authenticated, String expected) {
        String auth = canonicalUUID(authenticated);
        return !auth.isEmpty() && auth.equals(canonicalUUID(expected));
    }

    private static String canonicalUUID(String raw) {
        if (raw == null) return "";
        if (raw.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            raw = raw.replace("-", "");
        return raw.matches("(?i)[0-9a-f]{32}") ? raw.toLowerCase(Locale.ROOT) : "";
    }

    private static String safeReason(String reason, String fallback) {
        return reason != null && reason.matches("[a-z][a-z0-9_]{2,95}") ? reason : fallback;
    }

    private static boolean hex64(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
    private static String text(Map<String, Object> map, String key) {
        return map.get(key) instanceof String s ? s : "";
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?>)) throw new IllegalArgumentException("JSON object missing");
        return (Map<String, Object>) value;
    }

    /** Bounded parser: rejects duplicate keys, malformed escapes, excess nesting. */
    private static final class Json {
        private final String input;
        private int index;
        private Json(String input) { this.input = input; }
        static Map<String, Object> parse(String input) {
            if (input == null || input.length() > 262_144) throw new IllegalArgumentException("oversize response");
            Json p = new Json(input);
            Map<String, Object> result = object(p.value(0));
            p.space();
            if (p.index != input.length()) throw new IllegalArgumentException("trailing JSON");
            return result;
        }
        private void space() {
            while (index < input.length() && " \t\r\n".indexOf(input.charAt(index)) >= 0) index++;
        }
        private char next() {
            if (index >= input.length()) throw new IllegalArgumentException("truncated JSON");
            return input.charAt(index++);
        }
        private void expect(char expected) {
            if (next() != expected) throw new IllegalArgumentException("invalid JSON punctuation");
        }
        private Object value(int depth) {
            if (depth > 24) throw new IllegalArgumentException("JSON nesting limit");
            space();
            if (index >= input.length()) throw new IllegalArgumentException("empty JSON");
            return switch (input.charAt(index)) {
                case '{' -> objectValue(depth + 1);
                case '[' -> arrayValue(depth + 1);
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }
        private Map<String, Object> objectValue(int depth) {
            expect('{');
            Map<String, Object> output = new HashMap<>();
            space();
            if (index < input.length() && input.charAt(index) == '}') { index++; return output; }
            while (true) {
                space();
                if (index >= input.length() || input.charAt(index) != '"') throw new IllegalArgumentException("object key missing");
                String key = string();
                space(); expect(':');
                Object val = value(depth);
                if (output.containsKey(key)) throw new IllegalArgumentException("duplicate JSON key");
                output.put(key, val);
                space();
                char sep = next();
                if (sep == '}') return output;
                if (sep != ',') throw new IllegalArgumentException("object separator invalid");
            }
        }
        private List<Object> arrayValue(int depth) {
            expect('[');
            List<Object> output = new ArrayList<>();
            space();
            if (index < input.length() && input.charAt(index) == ']') { index++; return output; }
            while (true) {
                output.add(value(depth));
                space();
                char sep = next();
                if (sep == ']') return output;
                if (sep != ',') throw new IllegalArgumentException("array separator invalid");
            }
        }
        private String string() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                char ch = next();
                if (ch == '"') return out.toString();
                if (ch < 0x20) throw new IllegalArgumentException("control char in JSON");
                if (ch != '\\') { out.append(ch); continue; }
                char escape = next();
                switch (escape) {
                    case '"', '\\', '/' -> out.append(escape);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        if (index + 4 > input.length()) throw new IllegalArgumentException("invalid unicode escape");
                        String hex = input.substring(index, index + 4);
                        if (!hex.matches("[0-9a-fA-F]{4}")) throw new IllegalArgumentException("invalid unicode escape");
                        out.append((char) Integer.parseInt(hex, 16));
                        index += 4;
                    }
                    default -> throw new IllegalArgumentException("invalid JSON escape");
                }
            }
        }
        private Object literal(String expected, Object result) {
            if (!input.startsWith(expected, index)) throw new IllegalArgumentException("invalid JSON literal");
            index += expected.length();
            return result;
        }
        private Object number() {
            int start = index;
            if (input.charAt(index) == '-') index++;
            int digits = index;
            while (index < input.length() && Character.isDigit(input.charAt(index))) index++;
            if (digits == index) throw new IllegalArgumentException("invalid JSON number");
            if (index < input.length() && input.charAt(index) == '.') {
                index++;
                digits = index;
                while (index < input.length() && Character.isDigit(input.charAt(index))) index++;
                if (digits == index) throw new IllegalArgumentException("invalid JSON number");
            }
            if (index < input.length() && (input.charAt(index) == 'e' || input.charAt(index) == 'E')) {
                index++;
                if (index < input.length() && (input.charAt(index) == '+' || input.charAt(index) == '-')) index++;
                digits = index;
                while (index < input.length() && Character.isDigit(input.charAt(index))) index++;
                if (digits == index) throw new IllegalArgumentException("invalid JSON number");
            }
            try { return Double.valueOf(input.substring(start, index)); }
            catch (NumberFormatException e) { throw new IllegalArgumentException("invalid JSON number", e); }
        }
    }
}
