package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gitflic.ru/skif4er/launcher/cli/internal/devtools"
)

func devtoolsPrint03010(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func handleDevTools03010(args []string) error {
	if len(args) < 2 {
		return errors.New("Использование: nl devtools jar analyze|strip-debug, component test, auth serve")
	}
	switch args[0] {
	case "jar":
		switch args[1] {
		case "analyze":
			f := flag.NewFlagSet("devtools jar analyze", flag.ContinueOnError)
			input := f.String("input", "", "Путь к JAR")
			if e := f.Parse(args[2:]); e != nil {
				return e
			}
			if *input == "" || f.NArg() != 0 {
				return errors.New("Использование: devtools jar analyze --input path.jar")
			}
			r, e := devtools.AnalyzeJar(*input)
			if e != nil {
				return e
			}
			return devtoolsPrint03010(r)
		case "strip-debug":
			f := flag.NewFlagSet("devtools jar strip-debug", flag.ContinueOnError)
			input := f.String("input", "", "Исходный JAR")
			output := f.String("output", "", "Путь к новому JAR")
			if e := f.Parse(args[2:]); e != nil {
				return e
			}
			if *input == "" || *output == "" || f.NArg() != 0 {
				return errors.New("Использование: devtools jar strip-debug --input in.jar --output out.jar")
			}
			r, e := devtools.StripDebugJar(*input, *output)
			if e != nil {
				return e
			}
			return devtoolsPrint03010(r)
		}
	case "component":
		if args[1] != "test" {
			break
		}
		f := flag.NewFlagSet("devtools component test", flag.ContinueOnError)
		jar := f.String("jar", "", "JAR тестового компонента")
		java := f.String("java", "java", "Исполняемый файл Java")
		isolation := f.String("isolation", "sandbox", "sandbox (Linux bubblewrap) или process (только доверенный JAR)")
		ack := f.Bool("ack-unconfined", false, "Явно разрешить тестовую JVM без песочницы ОС")
		timeout := f.Duration("timeout", 15*time.Second, "Тайм-аут теста: от 1 с до 2 мин")
		heap := f.Int("heap-mb", 128, "Максимальный размер кучи JVM (не RSS)")
		rest := args[2:]
		var appArgs []string
		for i, a := range rest {
			if a == "--" {
				appArgs = append([]string{}, rest[i+1:]...)
				rest = rest[:i]
				break
			}
		}
		if e := f.Parse(rest); e != nil {
			return e
		}
		if f.NArg() != 0 || *jar == "" {
			return errors.New("Использование: devtools component test --jar example.jar [--isolation sandbox|process] [--ack-unconfined] [-- параметры...]")
		}
		if *isolation == "process" && !*ack {
			return errors.New("Режим процесса не обеспечивает изоляцию операционной системы; для подтверждения укажите --ack-unconfined")
		}
		r, e := devtools.RunComponent(context.Background(), devtools.ComponentOptions{Jar: *jar, Java: *java, Isolation: *isolation, Timeout: *timeout, HeapMB: *heap, Args: appArgs})
		if p := devtoolsPrint03010(r); p != nil {
			return p
		}
		return e
	case "auth":
		if args[1] != "serve" {
			break
		}
		f := flag.NewFlagSet("devtools auth serve", flag.ContinueOnError)
		listen := f.String("listen", "127.0.0.1:0", "Числовой адрес IPv4/IPv6 обратной петли")
		duration := f.Duration("duration", 5*time.Minute, "Максимальное время жизни тестовой среды")
		user := f.String("user", "debug-player", "Имя пользователя временной тестовой учётной записи")
		ack := f.Bool("ack-test-only", false, "Подтвердить использование учётной записи только для тестов")
		if e := f.Parse(args[2:]); e != nil {
			return e
		}
		if f.NArg() != 0 {
			return errors.New("Неожиданные аргументы команды")
		}
		if !*ack || os.Getenv("LAUNCHER_DEVTOOLS_TEST_MODE") != "1" {
			return errors.New("Политика тестовой идентификации отклонила запрос: установите LAUNCHER_DEVTOOLS_TEST_MODE=1 и --ack-test-only")
		}
		if *duration < time.Second || *duration > 30*time.Minute {
			return errors.New("Длительность тестового сценария: требуется значение от 1s до 30m")
		}
		fixture, e := devtools.NewFixtureServer(*user)
		if e != nil {
			return e
		}
		ln, e := devtools.ListenFixture(*listen, fixture)
		if e != nil {
			return e
		}
		server := &http.Server{Handler: fixture.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 8 * time.Second, MaxHeaderBytes: 8192}
		scheme := "http://"
		base := scheme + ln.Addr().String()
		if strings.Contains(ln.Addr().String(), ":") && strings.Count(ln.Addr().String(), ":") > 1 {
			base = scheme + ln.Addr().String()
		}
		if e := devtoolsPrint03010(map[string]any{"baseUrl": base, "testOnly": true, "username": fixture.User(), "password": fixture.Password(), "controlToken": fixture.ControlToken(), "expiresAfter": duration.String()}); e != nil {
			ln.Close()
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, *duration)
		defer cancel()
		go func() {
			<-ctx.Done()
			shutdown, c := context.WithTimeout(context.Background(), 2*time.Second)
			defer c()
			_ = server.Shutdown(shutdown)
		}()
		e = server.Serve(ln)
		if e != nil && !errors.Is(e, http.ErrServerClosed) {
			return fmt.Errorf("Ошибка сервера тестовой идентификации: %w", e)
		}
		return nil
	}
	return fmt.Errorf("Неизвестная операция инструментов разработчика %q", strings.Join(args[:2], " "))
}
