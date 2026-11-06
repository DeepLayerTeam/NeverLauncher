// texture-compat-02512 проверяет работающее локальное развёртывание
// Yggdrasil/authlib-injector, а не имитацию контракта. Оно получает, проверяет и
// декодирует настоящие подписанные профили и байты текстур с адресацией по
// содержимому из настроенного API.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"

	"gitflic.ru/skif4er/launcher/services/api/internal/texturepng"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponse02512 = 4 << 20

type options02512 struct {
	Origin, UUID                              string
	ExpectSkin, ExpectCape, AllowLoopbackHTTP bool
}
type report02512 struct {
	Status         string `json:"status"`
	ProfileID      string `json:"profileId"`
	SignatureValid bool   `json:"signatureValid"`
	SkinChecked    bool   `json:"skinChecked"`
	CapeChecked    bool   `json:"capeChecked"`
}

type metadata02512 struct {
	SkinDomains        []string `json:"skinDomains"`
	SignaturePublicKey string   `json:"signaturePublickey"`
}
type property02512 struct{ Name, Value, Signature string }
type profile02512 struct {
	ID, Name   string
	Properties []property02512
}
type textureEntry02512 struct {
	URL      string `json:"url"`
	Metadata struct {
		Model string `json:"model"`
	} `json:"metadata"`
}
type payload02512 struct {
	ProfileID, ProfileName string
	Textures               map[string]textureEntry02512
}

func main() {
	var opt options02512
	flag.StringVar(&opt.Origin, "origin", "", "исходный HTTPS-адрес API (без пути)")
	flag.StringVar(&opt.UUID, "uuid", "", "UUID локального профиля Minecraft")
	flag.BoolVar(&opt.ExpectSkin, "expect-skin", true, "требовать активный управляемый скин")
	flag.BoolVar(&opt.ExpectCape, "expect-cape", false, "требовать активный управляемый плащ")
	flag.BoolVar(&opt.AllowLoopbackHTTP, "allow-loopback-http", false, "permit http://127.0.0.1 for local disposable integration tests")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	result, err := certify02512(ctx, client, opt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "проверка совместимости текстур НЕ ПРОЙДЕНА:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cleanUUID02512(id string) (string, error) {
	id = strings.ToLower(strings.ReplaceAll(id, "-", ""))
	if len(id) != 32 {
		return "", errors.New("UUID Minecraft должен содержать 32 шестнадцатеричных символа")
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errors.New("Некорректный UUID Minecraft")
		}
	}
	return id, nil
}
func origin02512(raw string, allowLoopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return nil, errors.New("URL источника должен содержать только схему HTTP(S) и хост, без пути, учётных данных и параметров запроса")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if u.Scheme != "http" || !allowLoopback || !isLoopback02512(u.Hostname()) {
		return nil, errors.New("Требуется HTTPS; HTTP допустим только для явно заданного локального теста")
	}
	return u, nil
}
func isLoopback02512(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
func fetch02512(ctx context.Context, c *http.Client, raw string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s HTTP %d", req.URL.Path, resp.StatusCode)
	}
	if resp.ContentLength > maxResponse02512 {
		return nil, errors.New("Превышен допустимый размер: ответ профиля или текстуры")
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse02512+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxResponse02512 {
		return nil, errors.New("Превышен допустимый размер: ответ профиля или текстуры")
	}
	return content, nil
}
func domainAllowed02512(host string, domains []string) bool {
	host = strings.ToLower(host)
	for _, domain := range domains {
		domain = strings.ToLower(domain)
		if domain == host || strings.HasPrefix(domain, ".") && strings.HasSuffix(host, domain) && len(host) > len(domain) {
			return true
		}
	}
	return false
}
func checkTexture02512(ctx context.Context, c *http.Client, raw string, kind, model string, meta metadata02512, origin *url.URL, loopback bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != origin.Scheme && !(u.Scheme == "https" && origin.Scheme == "http") {
		return errors.New("Некорректное значение: текстура URL")
	}
	if u.Scheme != "https" && !(loopback && u.Scheme == "http" && isLoopback02512(u.Hostname())) {
		return errors.New("Небезопасный URL текстуры")
	}
	if !domainAllowed02512(u.Hostname(), meta.SkinDomains) {
		return errors.New("Хост текстуры отсутствует в списке разрешённых authlib-injector")
	}
	if strings.ToLower(u.Hostname()) != strings.ToLower(origin.Hostname()) {
		return errors.New("Хост текстуры отличается от проверенного исходного адреса API; внешняя загрузка запрещена проверкой")
	}
	if u.Port() != origin.Port() {
		return errors.New("Порт текстуры отличается от порта исходного API")
	}
	const prefix = "/api/v1/textures/blob/"
	if !strings.HasPrefix(u.Path, prefix) {
		return errors.New("Текстура не является управляемым двоичным объектом")
	}
	digest := strings.TrimPrefix(u.Path, prefix)
	if len(digest) != 64 {
		return errors.New("Некорректное значение: «хеш содержимого»")
	}
	if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
		return errors.New("Некорректное значение: «хеш в нижнем регистре»")
	}
	content, err := fetch02512(ctx, c, u.String())
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != digest {
		return errors.New("Не совпадает: текстура SHA-256; ожидается открытый URL")
	}
	// Используйте тот же полный парсер и ограничения геометрии, что и при
	// промышленной загрузке: CRC, анимация, хвостовые байты, ограничения пикселей и
	// настоящее распаковывание.
	if _, err := texturepng.Process(bytes.NewReader(content), kind, model); err != nil {
		return fmt.Errorf("Некорректное значение: управляемый %s PNG: %w", kind, err)
	}
	return nil
}
func certify02512(ctx context.Context, client *http.Client, opt options02512) (report02512, error) {
	report := report02512{Status: "failed"}
	uid, err := cleanUUID02512(opt.UUID)
	if err != nil {
		return report, err
	}
	origin, err := origin02512(opt.Origin, opt.AllowLoopbackHTTP)
	if err != nil {
		return report, err
	}
	metadataRaw, err := fetch02512(ctx, client, origin.String()+"/")
	if err != nil {
		return report, fmt.Errorf("Ошибка метаданных Yggdrasil: %w", err)
	}
	var metadata metadata02512
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		return report, err
	}
	if !domainAllowed02512(origin.Hostname(), metadata.SkinDomains) {
		return report, errors.New("Метаданные не разрешают исходный адрес API")
	}
	block, _ := pem.Decode([]byte(metadata.SignaturePublicKey))
	if block == nil {
		return report, errors.New("В метаданных отсутствует открытый ключ PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return report, err
	}
	key, ok := pub.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 {
		return report, errors.New("authlib-injector signing key: требуется «RSA >= 2048 bits»")
	}
	raw, err := fetch02512(ctx, client, origin.String()+"/sessionserver/session/minecraft/profile/"+uid+"?unsigned=false")
	if err != nil {
		return report, err
	}
	var profile profile02512
	if err := json.Unmarshal(raw, &profile); err != nil {
		return report, err
	}
	if profile.ID != uid || profile.Name == "" {
		return report, errors.New("Несовпадение: «идентичность профиля»")
	}
	if len(profile.Properties) != 1 || profile.Properties[0].Name != "textures" || profile.Properties[0].Signature == "" {
		return report, errors.New("В профиле отсутствует ровно одно подписанное свойство textures")
	}
	prop := profile.Properties[0]
	digest := sha1.Sum([]byte(prop.Value))
	sig, err := base64.StdEncoding.DecodeString(prop.Signature)
	if err != nil {
		return report, err
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA1, digest[:], sig); err != nil {
		return report, fmt.Errorf("Некорректное значение: «подпись текстуры RSA»: %w", err)
	}
	report.SignatureValid = true
	report.ProfileID = uid
	payloadBytes, err := base64.StdEncoding.DecodeString(prop.Value)
	if err != nil {
		return report, err
	}
	var payload payload02512
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return report, err
	}
	if payload.ProfileID != uid || payload.ProfileName != profile.Name {
		return report, errors.New("Несовпадение: «идентичность подписанного свойства текстуры»")
	}
	for _, kind := range []string{"SKIN", "CAPE"} {
		entry, found := payload.Textures[kind]
		required := kind == "SKIN" && opt.ExpectSkin || kind == "CAPE" && opt.ExpectCape
		if !found {
			if required {
				return report, fmt.Errorf("Отсутствует: «active %s texture»", kind)
			}
			continue
		}
		if kind == "SKIN" && entry.Metadata.Model != "" && entry.Metadata.Model != "slim" {
			return report, errors.New("Minecraft skin model: требуется «default или slim»")
		}
		model := "classic"
		if entry.Metadata.Model == "slim" {
			model = "slim"
		}
		if err := checkTexture02512(ctx, client, entry.URL, strings.ToLower(kind), model, metadata, origin, opt.AllowLoopbackHTTP); err != nil {
			return report, fmt.Errorf("%s: %w", kind, err)
		}
		if kind == "SKIN" {
			report.SkinChecked = true
		} else {
			report.CapeChecked = true
		}
	}
	report.Status = "passed"
	return report, nil
}
