package ru.launcher.sdk.core;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * Real per-extension Java SPI registry. Provider instances never enter the launcher's core
 * classpath. Selection drains outstanding calls, stops the old instance, starts the selected
 * instance and fails closed on a startup or compatibility failure. There is no global registry.
 * A hung third-party callback is interrupted at the deadline; the Go JVM process supervisor
 * remains the final boundary for code that ignores interruption.
 */
public final class ProviderRegistry implements AutoCloseable {
    private static final AtomicInteger THREAD_IDS = new AtomicInteger();
    private final ExtensionManifest manifest;
    private final RuntimeServices runtime;
    private final Cancellation cancellation;
    private final Object gate = new Object();
    private final Map<String, ServiceSlot> services = new LinkedHashMap<>();
    private final ExecutorService callbacks = Executors.newCachedThreadPool(r -> {
        Thread thread = new Thread(r, "neverext-spi-" + THREAD_IDS.incrementAndGet());
        thread.setDaemon(true);
        return thread;
    });
    private final ThreadLocal<Boolean> inProviderCallback = ThreadLocal.withInitial(() -> false);
    private final ThreadLocal<Boolean> inProviderCall = ThreadLocal.withInitial(() -> false);
    private boolean switching;
    private boolean closed;
    private final CountDownLatch terminated = new CountDownLatch(1);
    private volatile Exception shutdownFailure;
    private int inflight;

    private static final class ServiceSlot {
        final ProviderService<?> contract;
        final Map<String, ProviderDescriptor<?>> candidates = new LinkedHashMap<>();
        Active active;
        ServiceSlot(ProviderService<?> contract) { this.contract = contract; }
    }
    private record Active(ProviderDescriptor<?> descriptor, JavaProvider provider) {}
    public record Selection(String serviceId, String providerId, SemVer version) {}

    public ProviderRegistry(ExtensionManifest manifest, RuntimeServices runtime, Cancellation cancellation) {
        this.manifest = Objects.requireNonNull(manifest);
        this.runtime = runtime;
        this.cancellation = Objects.requireNonNull(cancellation);
    }
    public <T extends JavaProvider> void register(ProviderDescriptor<T> descriptor) {
        Objects.requireNonNull(descriptor);
        synchronized (gate) {
            requireOpen();
            if (switching) throw new IllegalStateException("provider selection in progress");
            if (services.size() >= 64 && !services.containsKey(descriptor.service().id()))
                throw new IllegalStateException("too many SPI services");
            ServiceSlot slot = services.computeIfAbsent(descriptor.service().id(), k -> new ServiceSlot(descriptor.service()));
            if (!slot.contract.equals(descriptor.service()))
                throw new IllegalArgumentException("conflicting SPI contract: " + descriptor.service().id());
            if (slot.candidates.size() >= 64) throw new IllegalStateException("too many SPI implementations");
            if (slot.candidates.containsKey(descriptor.id())) throw new IllegalArgumentException("duplicate SPI provider: " + descriptor.id());
            // Должны совпасть и API пакета расширения, и версия типа SPI, даже если провайдер
            // собран с другим выпуском SDK.
            SemVer api = SemVer.parse(manifest.api() + (manifest.api().chars().filter(c -> c == '.').count() == 1 ? ".0" : ""));
            if (!descriptor.service().version().matches(descriptor.supportedSpi()) ||
                    !api.matches(descriptor.supportedExtensionApi()))
                throw new CompatibilityException("incompatible SPI/API: " + descriptor.id());
            slot.candidates.put(descriptor.id(), descriptor);
        }
    }
    public List<String> candidates(String serviceId) {
        synchronized (gate) {
            ServiceSlot slot = services.get(serviceId);
            return slot == null ? List.of() : List.copyOf(slot.candidates.keySet());
        }
    }
    public Optional<Selection> selected(String serviceId) {
        synchronized (gate) {
            ServiceSlot slot = services.get(serviceId);
            if (closed || switching || slot == null || slot.active == null) return Optional.empty();
            Active active = slot.active;
            return Optional.of(new Selection(serviceId, active.descriptor.id(), active.descriptor.version()));
        }
    }
    /** Selects an already registered provider, with a *total* deadline including drain and callbacks. */
    public Selection select(String serviceId, String providerId, Duration timeout) throws Exception {
        checkTimeout(timeout);
        checkNotInsideProvider();
        long until = deadline(timeout);
        ServiceSlot slot;
        ProviderDescriptor<?> choice;
        Active prior;
        synchronized (gate) {
            requireOpen();
            if (switching) throw new IllegalStateException("concurrent SPI selection");
            slot = services.get(serviceId);
            if (slot == null || (choice = slot.candidates.get(providerId)) == null)
                throw new IllegalArgumentException("unregistered provider: " + serviceId + "/" + providerId);
            prior = slot.active;
            if (prior != null && prior.descriptor.id().equals(providerId))
                return new Selection(serviceId, providerId, prior.descriptor.version());
            switching = true;
            try {
                while (inflight != 0) awaitDeadline(until);
                requireOpen();
                slot.active = null; // fail closed before stopping the previous instance
            } catch (Exception e) { switching = false; gate.notifyAll(); throw e; }
        }
        try {
            if (prior != null) invokeLifecycle(prior.provider, false,
                    context(serviceId, prior.descriptor.id(), until), until);
            synchronized (gate) { requireOpen(); }
            JavaProvider next = construct(choice, until);
            try {
                invokeLifecycle(next, true, context(serviceId, providerId, until), until);
            } catch (Exception error) {
                try { invokeLifecycle(next, false, context(serviceId, providerId, until), until); }
                catch (Exception cleanup) { error.addSuppressed(cleanup); }
                throw error;
            }
            boolean abandon;
            synchronized (gate) {
                abandon = closed || cancellation.isCancelled();
                if (!abandon) slot.active = new Active(choice, next);
            }
            if (abandon) {
                try { invokeLifecycle(next, false, context(serviceId, providerId, until), until); }
                catch (Exception ignored) { /* process supervisor is the final stop boundary */ }
                throw new CancellationException("SPI registry closed during selection");
            }
            return new Selection(serviceId, providerId, choice.version());
        } finally {
            synchronized (gate) { switching = false; gate.notifyAll(); }
        }
    }
    /** Invoke the selected typed provider. Outstanding invocations drain before replacement. */
    public <T extends JavaProvider, R> R call(ProviderService<T> service, Function<T, R> action) {
        Objects.requireNonNull(service); Objects.requireNonNull(action);
        T selected;
        synchronized (gate) {
            requireOpen();
            if (switching) throw new IllegalStateException("SPI service is switching");
            ServiceSlot slot = services.get(service.id());
            if (slot == null || !slot.contract.equals(service)) throw new CompatibilityException("SPI contract mismatch: " + service.id());
            if (slot.active == null) throw new IllegalStateException("SPI provider not selected: " + service.id());
            selected = service.type().cast(slot.active.provider);
            inflight++;
        }
        boolean nested = inProviderCall.get();
        inProviderCall.set(true);
        try { return action.apply(selected); }
        finally {
            if (nested) inProviderCall.set(true); else inProviderCall.remove();
            synchronized (gate) { inflight--; gate.notifyAll(); }
        }
    }
    /** Drains operations and closes providers, even if Extension.stop() has failed. */
    public void shutdown(Duration timeout) throws Exception {
        checkTimeout(timeout);
        checkNotInsideProvider();
        long until = deadline(timeout);
        boolean joinExisting;
        synchronized (gate) {
            joinExisting = closed;
            if (!closed) { closed = true; gate.notifyAll(); }
        }
        if (joinExisting) {
            if (!terminated.await(remaining(until), TimeUnit.NANOSECONDS))
                throw new TimeoutException("concurrent SPI shutdown deadline exceeded");
            if (shutdownFailure != null) throw new IllegalStateException("previous SPI shutdown failed", shutdownFailure);
            return;
        }
        try {
            List<Map.Entry<String, Active>> active = new ArrayList<>();
            synchronized (gate) {
                while (switching || inflight != 0) awaitDeadline(until);
                for (var item : services.entrySet()) {
                    if (item.getValue().active != null) {
                        active.add(Map.entry(item.getKey(), item.getValue().active));
                        item.getValue().active = null;
                    }
                }
            }
            Exception failure = null;
            Collections.reverse(active);
            for (var item : active) {
                try { invokeLifecycle(item.getValue().provider, false,
                        context(item.getKey(), item.getValue().descriptor.id(), until), until); }
                catch (Exception error) {
                    if (failure == null) failure = error; else failure.addSuppressed(error);
                }
            }
            if (failure != null) throw failure;
        } catch (Exception error) {
            shutdownFailure = error;
            throw error;
        } finally {
            callbacks.shutdownNow();
            terminated.countDown();
        }
    }
    @Override public void close() {
        try { shutdown(Duration.ofSeconds(3)); }
        catch (Exception ignored) { callbacks.shutdownNow(); }
    }
    private void requireOpen() {
        if (closed || cancellation.isCancelled()) throw new IllegalStateException("SPI registry is closed");
    }
    private void checkNotInsideProvider() {
        if (inProviderCallback.get() || inProviderCall.get())
            throw new IllegalStateException("cannot select or shut down SPI from a provider callback");
    }
    private ProviderContext context(String serviceId, String providerId, long until) {
        long remain = Math.max(1, until - System.nanoTime());
        return new ProviderContext(manifest, serviceId, providerId, cancellation, Deadline.after(Duration.ofNanos(remain)), runtime);
    }
    private JavaProvider construct(ProviderDescriptor<?> descriptor, long until) throws Exception {
        JavaProvider value = bounded(() -> descriptor.factory().get(), until, descriptor.service().type().getClassLoader());
        if (value == null || !descriptor.service().type().isInstance(value))
            throw new CompatibilityException("factory returned incompatible SPI implementation: " + descriptor.id());
        return value;
    }
    private void invokeLifecycle(JavaProvider provider, boolean start, ProviderContext context, long until) throws Exception {
        bounded(() -> {
            if (start) provider.start(context); else provider.stop(context);
            return null;
        }, until, provider.getClass().getClassLoader());
    }
    private <T> T bounded(Callable<T> action, long until, ClassLoader implementationLoader) throws Exception {
        Future<T> work = callbacks.submit(() -> {
            inProviderCallback.set(true);
            Thread executing = Thread.currentThread();
            ClassLoader original = executing.getContextClassLoader();
            executing.setContextClassLoader(implementationLoader);
            try { return action.call(); }
            finally {
                executing.setContextClassLoader(original);
                inProviderCallback.remove();
            }
        });
        try { return work.get(remaining(until), TimeUnit.NANOSECONDS); }
        catch (TimeoutException e) { work.cancel(true); throw new TimeoutException("SPI callback deadline exceeded"); }
        catch (InterruptedException e) { work.cancel(true); Thread.currentThread().interrupt(); throw e; }
        catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) throw ex;
            throw new IllegalStateException("SPI callback failed", cause);
        }
    }
    private void awaitDeadline(long until) throws InterruptedException, TimeoutException {
        long left = remaining(until);
        TimeUnit.NANOSECONDS.timedWait(gate, left);
    }
    private static long remaining(long until) throws TimeoutException {
        long left = until - System.nanoTime();
        if (left <= 0) throw new TimeoutException("SPI operation deadline exceeded");
        return left;
    }
    private static long deadline(Duration timeout) { return System.nanoTime() + timeout.toNanos(); }
    private static void checkTimeout(Duration timeout) {
        Objects.requireNonNull(timeout);
        if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofMinutes(5)) > 0)
            throw new IllegalArgumentException("SPI timeout must be in (0,5m]");
    }
    public static final class CompatibilityException extends IllegalArgumentException {
        public CompatibilityException(String message) { super(message); }
    }
}
