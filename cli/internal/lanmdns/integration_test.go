package lanmdns

import (
	"net"
	"strings"
	"testing"
)

func TestMDNSGoodbyeAndInstanceCollision0498(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)
	local := net.ParseIP("192.168.42.7")
	live, err := announceMessage("World", 9443, fingerprint, []net.IP{local}, 120)
	if err != nil {
		t.Fatal(err)
	}
	if len(goodbyeInstances0498(live)) != 0 {
		t.Fatal("Отозвано действующее сетевое объявление")
	}
	if conflictingAdvertisement0498(live, "World", 9443, fingerprint, local) {
		t.Fatal("Собственное объявление ошибочно признано конфликтом")
	}
	other, err := announceMessage("World", 9443, fingerprint, []net.IP{net.ParseIP("192.168.42.8")}, 120)
	if err != nil {
		t.Fatal(err)
	}
	if !conflictingAdvertisement0498(other, "World", 9443, fingerprint, local) {
		t.Fatal("Не обнаружен конфликт имён")
	}
	changed, _ := announceMessage("World", 9443, strings.Repeat("cd", 32), []net.IP{local}, 120)
	if !conflictingAdvertisement0498(changed, "World", 9443, fingerprint, local) {
		t.Fatal("Не обнаружен конфликт сертификатов")
	}
	bye, _ := announceMessage("World", 9443, fingerprint, []net.IP{local}, 0)
	if !goodbyeInstances0498(bye)["world"] {
		t.Fatal("Сообщение goodbye не распознано")
	}
	if items, err := ParseAdvertisement(bye); err != nil || len(items) != 0 {
		t.Fatalf("Обнаружен уже отозванный сервис: %v %v", items, err)
	}
	if _, err := announceMessage("World", 9443, fingerprint, []net.IP{net.ParseIP("2001:db8::1")}, 120); err == nil {
		t.Fatal("Ответ DNS с IPv6 ошибочно засчитан как IPv4")
	}
}
