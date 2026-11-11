package ru.launcher.sdk.core;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Настоящие гонки выбора SPI, жизненного цикла и остановки без имитации реестра провайдеров. */
public final class ProviderRegistry0483Tests {
    private static int assertions;
    private static void ok(boolean yes, String label) { assertions++; if(!yes) throw new AssertionError(label); }
    private static void fails(Class<? extends Throwable> kind, Checked action) throws Exception {
        assertions++;
        try { action.run(); throw new AssertionError("ожидалось исключение " + kind.getName()); }
        catch (Throwable failure) { if(!kind.isInstance(failure)) throw new AssertionError("неожиданное исключение SPI", failure); }
    }
    @FunctionalInterface interface Checked { void run() throws Exception; }
    interface Greeting extends JavaProvider { String greet(String name); }
    static final ProviderService<Greeting> GREETING = new ProviderService<>("example.greeting", Greeting.class, SemVer.parse("1.1.0"));
    static final ExtensionManifest MANIFEST = ExtensionManifest.parse("{\"schemaVersion\":\"2.0\",\"id\":\"org.spi-tests\",\"name\":\"SPI Tests\",\"version\":\"0.1.0\",\"publisher\":\"test\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/spi.jar\"}]}");
    static class TestProvider implements Greeting {
        final String prefix; final AtomicInteger starts, stops;
        TestProvider(String prefix, AtomicInteger starts, AtomicInteger stops) { this.prefix=prefix; this.starts=starts; this.stops=stops; }
        public void start(ProviderContext context) throws Exception {
            ok(context.manifest().id().equals(MANIFEST.id()), "Провайдер получает подтверждённую идентичность расширения");
            ok(context.serviceId().equals(GREETING.id()), "Провайдер получает идентификатор службы");
            context.checkActive(); starts.incrementAndGet();
        }
        public void stop(ProviderContext context) { stops.incrementAndGet(); }
        public String greet(String name) { return prefix + name; }
    }
    static ProviderDescriptor<Greeting> desc(String name, String spi, String api, java.util.function.Supplier<Greeting> factory) {
        return new ProviderDescriptor<>(GREETING, name, SemVer.parse("1.2.0"), spi, api, factory);
    }
    static void switchingAndCompatibility() throws Exception {
        AtomicInteger starts=new AtomicInteger(),stops=new AtomicInteger(),constructors=new AtomicInteger();
        try(var registry=new ProviderRegistry(MANIFEST,null,new Cancellation())) {
            registry.register(desc("first",">=1.0.0 <2.0.0","^1.0.0",()->{constructors.incrementAndGet();return new TestProvider("one-",starts,stops);}));
            registry.register(desc("second","^1.0.0","1.0.0",()->{constructors.incrementAndGet();return new TestProvider("two-",starts,stops);}));
            ok(registry.candidates(GREETING.id()).equals(List.of("first","second")),"Порядок выбора провайдеров остаётся стабильным после регистрации");
            fails(ProviderRegistry.CompatibilityException.class,()->registry.register(desc("wrong-spi","^2.0.0","*",()->{constructors.incrementAndGet();return null;})));
            fails(ProviderRegistry.CompatibilityException.class,()->registry.register(desc("wrong-api","*","^3.7.0",()->{constructors.incrementAndGet();return null;})));
            ok(constructors.get()==0,"Несовместимые провайдеры отклоняются до создания экземпляра");
            fails(IllegalArgumentException.class,()->registry.register(desc("first","*","*",()->null)));
            fails(IllegalArgumentException.class,()->registry.register(new ProviderDescriptor<>(new ProviderService<>("example.greeting",Greeting.class,SemVer.parse("2.0.0")),"other",SemVer.parse("1.0.0"),"*","*",()->null)));
            fails(IllegalStateException.class,()->registry.call(GREETING,p->p.greet("Ada")));
            ok(registry.select(GREETING.id(),"first",Duration.ofSeconds(2)).providerId().equals("first"),"Первым выбран нужный провайдер");
            ok(registry.call(GREETING,p->p.greet("Ada")).equals("one-Ada"),"Проверен реальный типизированный вызов провайдера");
            registry.select(GREETING.id(),"second",Duration.ofSeconds(2));
            ok(registry.call(GREETING,p->p.greet("Ada")).equals("two-Ada"),"После выбора используется новый провайдер");
            ok(starts.get()==2&&stops.get()==1,"Старый провайдер корректно остановлен ровно один раз");
            ok(registry.selected(GREETING.id()).orElseThrow().providerId().equals("second"),"Активный провайдер доступен");
            registry.shutdown(Duration.ofSeconds(2));
            ok(stops.get()==2,"Активный провайдер остановлен при закрытии реестра");
            fails(IllegalStateException.class,()->registry.call(GREETING,p->p.greet("Ada")));
        }
    }
    static void failedActivationFailsClosed() throws Exception {
        AtomicInteger cleaned=new AtomicInteger();
        try(var registry=new ProviderRegistry(MANIFEST,null,new Cancellation())) {
            registry.register(desc("good","*","*",()->new TestProvider("good-",new AtomicInteger(),new AtomicInteger())));
            registry.register(desc("broken","*","*",()->new Greeting(){
                public void start(ProviderContext ctx){throw new IllegalStateException("startup-failure");}
                public void stop(ProviderContext ctx){cleaned.incrementAndGet();}
                public String greet(String name){return "wrong";}
            }));
            registry.select(GREETING.id(),"good",Duration.ofSeconds(2));
            fails(IllegalStateException.class,()->registry.select(GREETING.id(),"broken",Duration.ofSeconds(2)));
            ok(registry.selected(GREETING.id()).isEmpty(),"После неудачного переключения активный провайдер отсутствует");
            ok(cleaned.get()==1,"Провайдер с ошибкой корректно освобождает ресурсы после неудачного запуска");
            fails(IllegalStateException.class,()->registry.call(GREETING,p->p.greet("x")));
        }
    }
    static void callDrainAndSwitch() throws Exception {
        CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        AtomicInteger stopped=new AtomicInteger();AtomicReference<Throwable> failure=new AtomicReference<>();
        try(var registry=new ProviderRegistry(MANIFEST,null,new Cancellation())) {
            registry.register(desc("slow","*","*",()->new TestProvider("slow-",new AtomicInteger(),stopped)));
            registry.register(desc("fast","*","*",()->new TestProvider("fast-",new AtomicInteger(),new AtomicInteger())));
            registry.select(GREETING.id(),"slow",Duration.ofSeconds(1));
            Thread reader=new Thread(()->{try{registry.call(GREETING,p->{entered.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}return p.greet("Z");});}catch(Throwable t){failure.set(t);}});
            reader.start();
            ok(entered.await(1,TimeUnit.SECONDS),"Вызов провайдера начат");
            Thread switching=new Thread(()->{try{registry.select(GREETING.id(),"fast",Duration.ofSeconds(2));}catch(Throwable t){failure.set(t);}});
            switching.start();
            Thread.sleep(80);
            ok(stopped.get()==0&&switching.isAlive(),"Провайдер не останавливается во время активного вызова");
            release.countDown();reader.join(1200);switching.join(1200);
            ok(!reader.isAlive()&&!switching.isAlive()&&failure.get()==null,"Переключение дожидается завершения текущих вызовов");
            ok(stopped.get()==1,"Предыдущий провайдер остановлен после завершения вызовов");
        } finally {release.countDown();}
    }
    static void deadlineAndFailure() throws Exception {
        CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        try(var registry=new ProviderRegistry(MANIFEST,null,new Cancellation())) {
            registry.register(desc("stuck","*","*",()->new Greeting(){
                public void start(ProviderContext ctx){entered.countDown();while(release.getCount()!=0){try{release.await(50,TimeUnit.MILLISECONDS);}catch(InterruptedException ignored){}}}
                public void stop(ProviderContext ctx){}
                public String greet(String name){return name;}
            }));
            long begin=System.nanoTime();
            fails(TimeoutException.class,()->registry.select(GREETING.id(),"stuck",Duration.ofMillis(110)));
            ok(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-begin)<750,"Время ожидания зависшего запуска ограничено");
            ok(entered.getCount()==0&&registry.selected(GREETING.id()).isEmpty(),"По истечении времени ожидания провайдер не публикуется");
        } finally {release.countDown();}
    }
    static void lifecycleIntegration() throws Exception {
        AtomicInteger starts=new AtomicInteger(),stops=new AtomicInteger();
        Extension extension=new Extension(){
            public void start(ExtensionContext ctx) throws Exception {
                ok(ctx.providers()!=null,"Реальный жизненный цикл расширения предоставляет реестр SPI");
                ctx.providers().register(desc("life","*","*",()->new TestProvider("hello-",starts,stops)));
                ctx.providers().select(GREETING.id(),"life",Duration.ofSeconds(1));
                ok(ctx.providers().call(GREETING,p->p.greet("a")).equals("hello-a"),"Провайдер активен при запуске расширения");
            }
            public void stop(ExtensionContext ctx){ok(ctx.providers().selected(GREETING.id()).isPresent(),"Провайдер остаётся доступным при остановке расширения");}
        };
        try(var lifecycle=new ExtensionLifecycle(extension,MANIFEST)) {
            lifecycle.start(Duration.ofSeconds(2));
            ok(lifecycle.state()==ExtensionLifecycle.State.RUNNING,"Расширение SPI переходит в состояние RUNNING");
            lifecycle.stop(Duration.ofSeconds(2));
            ok(lifecycle.state()==ExtensionLifecycle.State.STOPPED,"Расширение SPI переходит в состояние STOPPED");
        }
        ok(starts.get()==1&&stops.get()==1,"При остановке расширения провайдер закрывается автоматически");
    }
    static void recursiveSwitchRejected() throws Exception {
        try(var registry=new ProviderRegistry(MANIFEST,null,new Cancellation())) {
            registry.register(desc("one","*","*",()->new TestProvider("one-",new AtomicInteger(),new AtomicInteger())));
            registry.select(GREETING.id(),"one",Duration.ofSeconds(1));
            fails(IllegalStateException.class,()->registry.call(GREETING,p->{
                try {registry.select(GREETING.id(),"other",Duration.ofSeconds(1));}
                catch(Exception e){throw new IllegalStateException("повторный вход в выбор отклонён",e);}
                return p.greet("x");
            }));
            ok(registry.selected(GREETING.id()).isPresent(),"Рекурсивное переключение не нарушает работу активного провайдера");
        }
    }
    static void concurrentShutdown() throws Exception {
        CountDownLatch stopping=new CountDownLatch(1),finish=new CountDownLatch(1);
        AtomicInteger stops=new AtomicInteger();AtomicReference<Throwable> failure=new AtomicReference<>();
        try(var registry=new ProviderRegistry(MANIFEST,null,new Cancellation())) {
            registry.register(desc("shutdown","*","*",()->new Greeting(){
                public void start(ProviderContext ctx) {}
                public void stop(ProviderContext ctx) throws Exception {stops.incrementAndGet();stopping.countDown();finish.await();}
                public String greet(String name){return name;}
            }));
            registry.select(GREETING.id(),"shutdown",Duration.ofSeconds(1));
            Thread one=new Thread(()->{try{registry.shutdown(Duration.ofSeconds(3));}catch(Throwable e){failure.set(e);}});
            Thread two=new Thread(()->{try{registry.shutdown(Duration.ofSeconds(3));}catch(Throwable e){failure.set(e);}});
            one.start();
            try {
                ok(stopping.await(1,TimeUnit.SECONDS),"Первое завершение работы приступило к остановке провайдера");
                two.start();Thread.sleep(70);
                ok(two.isAlive(),"Параллельное завершение ожидает фактической остановки провайдера");
            } finally {finish.countDown();one.join(1100);two.join(1100);}
            ok(!one.isAlive()&&!two.isAlive()&&failure.get()==null,"Оба параллельных завершения выполнены");
            ok(stops.get()==1,"Остановка провайдера выполняется один раз");
        }
    }
    static void failedExtensionStartCleansProvider() throws Exception {
        AtomicInteger stopped=new AtomicInteger();
        Extension failing=new Extension(){
            public void start(ExtensionContext ctx) throws Exception {
                ctx.providers().register(desc("error","*","*",()->new TestProvider("hello",new AtomicInteger(),stopped)));
                ctx.providers().select(GREETING.id(),"error",Duration.ofSeconds(1));
                throw new IllegalArgumentException("запуск расширения отклонён");
            }
            public void stop(ExtensionContext ctx) { throw new AssertionError("нельзя останавливать незапущенное расширение"); }
        };
        try(var lifecycle=new ExtensionLifecycle(failing,MANIFEST)) {
            fails(IllegalArgumentException.class,()->lifecycle.start(Duration.ofSeconds(2)));
            ok(lifecycle.state()==ExtensionLifecycle.State.FAILED,"Неудачный запуск не отмечается как работающий");
            ok(stopped.get()==1,"Неудачный запуск закрывает ранее активированный провайдер");
        }
    }
    public static void main(String[] args) throws Exception {
        switchingAndCompatibility(); failedActivationFailsClosed(); callDrainAndSwitch(); deadlineAndFailure(); lifecycleIntegration();
        concurrentShutdown(); failedExtensionStartCleansProvider(); recursiveSwitchRejected();
        System.out.println("PASS: "+assertions+" проверок реестра Java SPI, совместимости, жизненного цикла и параллельного завершения");
    }
}
