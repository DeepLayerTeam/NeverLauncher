package main

// Нативное проверяемое свидетельство игровой сессии для изолированной репетиции миграции с отказом
// при неопределённости. В отличие от скриптов проверки, предоставленных оператором, этот код
// запускает настоящий клиент в активном режиме и наблюдает его UUID на живом сервере Java через
// аутентифицированный RCON loopback. Учётные данные RCON, вывод клиента и argv не отправляются в
// Backend. Это наблюдение в тестовом окружении оператора, а не удалённая аттестация клиента и не
// доказательство лицензии Minecraft.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type rehearsalLiveConfig0447 struct {
	ClientPath       string   `json:"clientPath"`
	ClientArgs       []string `json:"clientArgs"`
	PlayerName       string   `json:"playerName"`
	PlayerUUID       string   `json:"playerUuid"`
	RCONAddress      string   `json:"rconAddress"`
	RCONPasswordFile string   `json:"rconPasswordFile"`
	TimeoutSeconds   int      `json:"timeoutSeconds"`
}

type rehearsalLiveWitness0447 struct {
	ClientSHA256 string `json:"clientSha256"`
	PlayerName   string `json:"playerName"`
	PlayerUUID   string `json:"playerUuid"`
	BeforeSHA256 string `json:"beforeSha256"`
	JoinedSHA256 string `json:"joinedSha256"`
	StartedAt    string `json:"startedAt"`
	JoinedAt     string `json:"joinedAt"`
}

var rehearsalPlayerName0447 = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)
var rehearsalUUID0447 = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func rehearsalReadLiveConfig0447(root string) (rehearsalLiveConfig0447, error) {
	var cfg rehearsalLiveConfig0447
	raw, err := rehearsalRead03310(root, "live-session.json", 16<<10)
	if err != nil {
		return cfg, fmt.Errorf("Требуется: «live-session.json»: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return cfg, errors.New("В конфигурации текущей сессии обнаружены лишние данные")
	}
	if !rehearsalPlayerName0447.MatchString(cfg.PlayerName) || !rehearsalUUID0447.MatchString(cfg.PlayerUUID) || len(cfg.ClientArgs) > 128 || cfg.TimeoutSeconds < 10 || cfg.TimeoutSeconds > 600 {
		return cfg, errors.New("Некорректное значение: игрок, аргументы клиента или время ожидания")
	}
	if cfg.ClientPath == "" || cfg.RCONPasswordFile == "" {
		return cfg, errors.New("Требуется: поля clientPath и rconPasswordFile")
	}
	for _, s := range cfg.ClientArgs {
		if len(s) > 4096 || strings.ContainsRune(s, 0) {
			return cfg, errors.New("Некорректное значение: аргумент клиента")
		}
	}
	host, port, err := net.SplitHostPort(cfg.RCONAddress)
	if err != nil {
		return cfg, errors.New("Некорректное значение: RCON адрес")
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n <= 0 || n > 65535 {
		return cfg, errors.New("Для RCON требуется: на числовом локальном адресе обратной связи с допустимым портом")
	}
	return cfg, nil
}

func rehearsalRCONPacket0447(w io.Writer, id, kind int32, body string) error {
	if len(body) > 4096 {
		return errors.New("Запрос RCON превышает допустимый размер")
	}
	raw := make([]byte, 14+len(body))
	binary.LittleEndian.PutUint32(raw[:4], uint32(len(raw)-4))
	binary.LittleEndian.PutUint32(raw[4:8], uint32(id))
	binary.LittleEndian.PutUint32(raw[8:12], uint32(kind))
	copy(raw[12:], body)
	_, err := w.Write(raw)
	return err
}
func rehearsalRCONRead0447(r io.Reader) (int32, int32, string, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return 0, 0, "", err
	}
	n := binary.LittleEndian.Uint32(prefix[:])
	if n < 10 || n > 16384 {
		return 0, 0, "", errors.New("Некорректное значение: длина пакета RCON")
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return 0, 0, "", err
	}
	if raw[len(raw)-1] != 0 || raw[len(raw)-2] != 0 {
		return 0, 0, "", errors.New("Некорректное значение: терминатор RCON")
	}
	return int32(binary.LittleEndian.Uint32(raw[:4])), int32(binary.LittleEndian.Uint32(raw[4:8])), string(raw[8 : len(raw)-2]), nil
}

func rehearsalRCONList0447(ctx context.Context, address, password string) (string, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	c, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("Недоступно: RCON тестового окружения: %w", err)
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 4*time.Second {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	}
	if err = rehearsalRCONPacket0447(c, 71, 3, password); err != nil {
		return "", err
	}
	authorized := false
	for i := 0; i < 3; i++ {
		id, kind, _, e := rehearsalRCONRead0447(c)
		if e != nil {
			return "", e
		}
		if id == -1 {
			return "", errors.New("Аутентификация RCON отклонена")
		}
		if id == 71 && kind == 2 {
			authorized = true
			break
		}
	}
	if !authorized {
		return "", errors.New("Подтверждение аутентификации RCON не получено")
	}
	if err = rehearsalRCONPacket0447(c, 72, 2, "list uuids"); err != nil {
		return "", err
	}
	for i := 0; i < 3; i++ {
		id, _, text, e := rehearsalRCONRead0447(c)
		if e != nil {
			return "", e
		}
		if id == 72 {
			return text, nil
		}
	}
	return "", errors.New("Отсутствует: ответ RCON со списком UUID")
}
func rehearsalRCONHasPlayer0447(result, name, uuid string) bool {
	// Команда Java Edition /list uuids выводит `PlayerName (uuid)`. Не принимайте UUID
	// из другого места сообщения или записи другого игрока.
	pattern := regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_])` + regexp.QuoteMeta(name) + `\s*\(\s*` + regexp.QuoteMeta(uuid) + `\s*\)`)
	return pattern.MatchString(result)
}
func rehearsalHashFile0447(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 512<<20 {
		return "", errors.New("Некорректное значение: размер исполняемого файла клиента")
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (512<<20)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func rehearsalLaunchLive0447(ctx context.Context, root string, snapshot rehearsalSnapshot03310) (rehearsalLiveWitness0447, func() error, func(), error) {
	var proof rehearsalLiveWitness0447
	noop := func() {}
	noverify := func() error { return errors.New("Нет активного сеанса") }
	cfg, err := rehearsalReadLiveConfig0447(root)
	if err != nil {
		return proof, noverify, noop, err
	}
	mapped := false
	for _, p := range snapshot.Players {
		if p.UUID == cfg.PlayerUUID {
			mapped = true
			break
		}
	}
	if !mapped {
		return proof, noverify, noop, errors.New("UUID активного игрока отсутствует в исходном снимке")
	}
	executable, err := rehearsalPath03310(root, cfg.ClientPath)
	if err != nil {
		return proof, noverify, noop, err
	}
	st, err := os.Stat(executable)
	if err != nil {
		return proof, noverify, noop, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return proof, noverify, noop, errors.New("Клиент не является обычным исполняемым файлом")
	}
	hash, err := rehearsalHashFile0447(executable)
	if err != nil {
		return proof, noverify, noop, err
	}
	passwordBytes, err := rehearsalRead03310(root, cfg.RCONPasswordFile, 4096)
	if err != nil {
		return proof, noverify, noop, fmt.Errorf("Ошибка файла учётных данных RCON: %w", err)
	}
	password := strings.TrimRight(string(passwordBytes), "\r\n")
	if password == "" || strings.ContainsAny(password, "\r\n\x00") {
		return proof, noverify, noop, errors.New("Некорректное значение: учётные данные RCON тестового окружения")
	}
	defer func() {
		for i := range passwordBytes {
			passwordBytes[i] = 0
		}
	}()
	preCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	before, err := rehearsalRCONList0447(preCtx, cfg.RCONAddress, password)
	cancel()
	if err != nil {
		return proof, noverify, noop, err
	}
	if rehearsalRCONHasPlayer0447(before, cfg.PlayerName, cfg.PlayerUUID) {
		return proof, noverify, noop, errors.New("Игрок уже находится в сети до запуска подготовленного клиента")
	}
	clientCtx, stop := context.WithCancel(ctx)
	cmd := exec.CommandContext(clientCtx, executable, cfg.ClientArgs...)
	cmd.Dir = root
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "LANG=C.UTF-8"}
	for _, key := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if v, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	// Отбрасывайте весь вывод процесса. Журналы игры могут содержать токены; их нельзя
	// копировать в доказательства, stdout, API или диагностический архив.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		stop()
		return proof, noverify, noop, fmt.Errorf("Ошибка: запуск клиента: %w", err)
	}
	exited := make(chan error, 1)
	finished := make(chan struct{})
	go func() { exited <- cmd.Wait(); close(finished) }()
	verify := func() error {
		select {
		case <-finished:
			return errors.New("Процесс подготовленного клиента завершился до окончания репетиционной проверки")
		default:
		}
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		answer, err := rehearsalRCONList0447(queryCtx, cfg.RCONAddress, password)
		cancel()
		if err != nil || !rehearsalRCONHasPlayer0447(answer, cfg.PlayerName, cfg.PlayerUUID) {
			return errors.New("Тестовый игрок покинул сервер до окончания репетиционной проверки")
		}
		select {
		case <-finished:
			return errors.New("Процесс подготовленного клиента завершился во время репетиционной проверки")
		default:
		}
		return nil
	}
	cleanup := func() {
		stop()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
		}
	}
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()
	started := time.Now().UTC()
	deadline := time.NewTimer(time.Duration(cfg.TimeoutSeconds) * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(1200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case e := <-exited:
			return proof, noverify, noop, fmt.Errorf("Клиент завершился до подтверждённого подключения к серверу: %v", e)
		case <-ctx.Done():
			return proof, noverify, noop, ctx.Err()
		case <-deadline.C:
			return proof, noverify, noop, errors.New("Клиент не подключился к тестовому серверу в установленный срок")
		case <-tick.C:
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			answer, qerr := rehearsalRCONList0447(qctx, cfg.RCONAddress, password)
			cancel()
			if qerr != nil {
				continue
			}
			if !rehearsalRCONHasPlayer0447(answer, cfg.PlayerName, cfg.PlayerUUID) {
				continue
			}
			// Повторно проверьте ТУ ЖЕ живую сессию после периода ожидания. Кэшированные журналы и успешное
			// завершение лаунчера не заменяют активного подключения к многопользовательскому серверу.
			select {
			case e := <-exited:
				return proof, noverify, noop, fmt.Errorf("Клиент завершился во время подключения: %v", e)
			case <-ctx.Done():
				return proof, noverify, noop, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			qctx, cancel = context.WithTimeout(ctx, 5*time.Second)
			confirmed, checkErr := rehearsalRCONList0447(qctx, cfg.RCONAddress, password)
			cancel()
			if checkErr != nil || !rehearsalRCONHasPlayer0447(confirmed, cfg.PlayerName, cfg.PlayerUUID) {
				continue
			}
			select {
			case e := <-exited:
				return proof, noverify, noop, fmt.Errorf("Клиент завершился во время подтверждения: %v", e)
			default:
			}
			h1 := sha256.Sum256([]byte(before))
			h2 := sha256.Sum256([]byte(confirmed))
			proof = rehearsalLiveWitness0447{ClientSHA256: hash, PlayerName: cfg.PlayerName, PlayerUUID: cfg.PlayerUUID, BeforeSHA256: hex.EncodeToString(h1[:]), JoinedSHA256: hex.EncodeToString(h2[:]), StartedAt: started.Format(time.RFC3339Nano), JoinedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			success = true
			return proof, verify, cleanup, nil
		}
	}
}
