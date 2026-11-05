package main

// Проверяйте границу шифрования предоставленного пользователем Java-сервера
// Minecraft. Это проверка без учётных данных: она не отправляет токены и не
// утверждает успешный игровой вход. Передавайте только серверы, которыми оператор
// владеет или вправе проверять.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

var ErrNoOnlineModeChallenge = errors.New("Сервер не выдал проверочный запрос шифрования для сетевого режима")

func putVarInt(b []byte, x int) []byte {
	for {
		if x & ^0x7f == 0 {
			return append(b, byte(x))
		}
		b = append(b, byte(x&0x7f|0x80))
		x = int(uint(x) >> 7)
	}
}
func readVarInt(r *bufio.Reader) (int, error) {
	n := 0
	for i := 0; i < 5; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n |= int(b&127) << (7 * i)
		if b&128 == 0 {
			return n, nil
		}
	}
	return 0, errors.New("Превышен допустимый размер: переменное целое протокола")
}
func writeFrame(w io.Writer, body []byte) error {
	if len(body) > 32767 {
		return errors.New("Превышен допустимый размер: пакет")
	}
	frame := putVarInt(nil, len(body))
	frame = append(frame, body...)
	_, err := w.Write(frame)
	return err
}
func probeOnlineMode(ctx context.Context, address string, protocol int) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return errors.New("Адрес сервера: требуется хост:порт")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || protocol < 1 || protocol > 1000000 {
		return errors.New("Некорректное значение: порт или протокол сервера")
	}
	if protocol < 764 {
		return errors.New("Проверка поддерживает только Minecraft 1.20.2 и новее")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("Ошибка: TCP-соединение с сервером")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	// Стандартное рукопожатие входа, затем Login Start; НЕ передавайте настоящее
	// имя пользователя, UUID или учётные данные в ходе пробы.
	payload := putVarInt(nil, 0)
	payload = putVarInt(payload, protocol)
	if len(host) > 255 {
		return errors.New("Имя хоста слишком длинное")
	}
	payload = putVarInt(payload, len(host))
	payload = append(payload, host...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(port))
	payload = putVarInt(payload, 2) // next state Login
	if err := writeFrame(conn, payload); err != nil {
		return errors.New("Ошибка: установление соединения с сервером")
	}
	login := putVarInt(nil, 0)
	name := "NLProbe26" // не настоящее имя пользователя допустимого игрока
	login = putVarInt(login, len(name))
	login = append(login, name...)
	if protocol >= 764 { // Для версии 1.20.2+ в Login Start обязателен UUID (16 байт).
		login = append(login, make([]byte, 16)...)
	} else if protocol >= 759 {
		// Современные варианты Login Start до 1.20.2 не сертифицируются этой пробой;
		// не сообщайте о ложных ошибках шифрования.
		return errors.New("Проверка поддерживает только протоколы Minecraft 1.20.2 и новее")
	}
	if err := writeFrame(conn, login); err != nil {
		return errors.New("Ошибка: начало входа на сервер")
	}
	reader := bufio.NewReaderSize(conn, 8192)
	size, err := readVarInt(reader)
	if err != nil {
		return ErrNoOnlineModeChallenge
	}
	if size <= 0 || size > 8192 {
		return ErrNoOnlineModeChallenge
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(reader, packet); err != nil {
		return ErrNoOnlineModeChallenge
	}
	packetReader := bufio.NewReader(bytes.NewReader(packet))
	id, err := readVarInt(packetReader)
	if err != nil || id != 1 {
		return ErrNoOnlineModeChallenge
	}
	// В состоянии входа 0x01 означает Encryption Request. Проверяйте наличие
	// открытого ключа в запросе; одного байта 0x01 недостаточно.
	idLength, err := readVarInt(packetReader) // длина строки serverId
	if err != nil || idLength < 0 || idLength > 64 {
		return ErrNoOnlineModeChallenge
	}
	if _, err := io.CopyN(io.Discard, packetReader, int64(idLength)); err != nil {
		return ErrNoOnlineModeChallenge
	}
	keyLength, err := readVarInt(packetReader)
	if err != nil || keyLength < 64 || keyLength > 4096 {
		return ErrNoOnlineModeChallenge
	}
	key := make([]byte, keyLength)
	if _, err := io.ReadFull(packetReader, key); err != nil {
		return ErrNoOnlineModeChallenge
	}
	parsed, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return ErrNoOnlineModeChallenge
	}
	if _, ok := parsed.(*rsa.PublicKey); !ok {
		return ErrNoOnlineModeChallenge
	}
	return nil
}
