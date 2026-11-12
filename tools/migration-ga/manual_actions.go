package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func markdownSafe(s string) string {
	s = strings.Map(func(c rune) rune {
		if c == '\n' || c == '\r' || c == 0 {
			return ' '
		}
		return c
	}, s)
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "'")
	return strings.TrimSpace(s)
}

// Выгружайте все незавершённые ручные операции из неизменяемого отчёта;
// это список задач оператора, а НЕ утверждение об их выполнении.
func renderManualWorklist(p Plan, r Report) ([]byte, error) {
	if err := reportVerified(r); err != nil {
		return nil, err
	}
	if p.RunID != r.RunID || p.ProjectID != r.ProjectID {
		return nil, errors.New("Список ручных операций относится к другому проекту")
	}
	items := append([]Item(nil), r.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].Kind+items[i].Source < items[j].Kind+items[j].Source })
	var b strings.Builder
	fmt.Fprintf(&b, "# Gravit → Launcher: список ручных действий по миграции и откату\n\n")
	fmt.Fprintf(&b, "- Запуск: `%s`\n- Проект: `%s`\n- SHA-256 источника: `%s`\n- SHA-256 отчёта: `%s`\n- SHA-256 целевого релиза: `%s`\n", markdownSafe(r.RunID), markdownSafe(r.ProjectID), r.SourceSHA256, r.ReportSHA256, p.TargetReleaseSHA256)
	fmt.Fprintf(&b, "\n## Ручные действия с исходной системой (%d)\n\n", r.Counts["manual"])
	n := 0
	for _, item := range items {
		if item.Status == "manual" {
			n++
			fmt.Fprintf(&b, "- [ ] **%s** — `%s`", markdownSafe(item.Kind), markdownSafe(item.Source))
			if item.Target != "" {
				fmt.Fprintf(&b, " → `%s`", markdownSafe(item.Target))
			}
			if item.Reason != "" {
				fmt.Fprintf(&b, "; %s", markdownSafe(item.Reason))
			}
			b.WriteByte('\n')
		}
	}
	if n == 0 {
		b.WriteString("В этом отчёте нет операций для ручной обработки. Указанные ниже проверки оператора по-прежнему обязательны.\n")
	}
	b.WriteString(`
## Обязательные проверки оператора перед переключением

- [ ] Зафиксировать, какие именно миры Minecraft, внешние базы SQL, маршруты прокси, DNS-записи и пользовательские расширения находятся за пределами автоматической миграции.
- [ ] Подтвердить владение учётной записью и процедуру сброса пароля для каждого игрока, который не может войти. Не использовать повторно токены Gravit, старые ключи и разрешения.
- [ ] Остановить либо изолировать **все** процессы Gravit и Launcher, способные записывать данные. Одной маскировки служб systemd недостаточно для подтверждения остановки остальных процессов.
- [ ] Создать независимые резервные копии миров, инвентаря, экономики, баз данных, плагинов, настроек и секретов, пригодные для восстановления.
- [ ] Создать *два разных* каталога снимков источника и цели с файлами world/, plugins/, player-uuids.txt. Выполнить audit-state перед переключением и после учебного отката.
- [ ] Проверить реальный вход Java/Minecraft и подключение к серверу с перенесённым UUID для каждого настроенного эталонного класса.
- [ ] Повторно проверить каждое ручное действие из списка выше. Записать ответственного оператора, время завершения и расположение закрытых доказательств в заявку на изменение.

## Ограничения отката и точка невозврата

- [ ] Назначить ограниченное окно переключения и зафиксировать исходные редакции маршрутов прокси/DNS и подписанного релиза.
- [ ] Подтвердить блокировку записывающего процесса Launcher до возврата трафика к Gravit.
- [ ] Если после переключения игроки изменили миры, инвентарь, экономику, привилегии или данные плагинов в SQL, **нельзя** восстанавливать устаревшую копию Gravit. Сначала необходимо согласовать изменённые данные и независимо проверить результат.
- [ ] Проверить свежие снимки, точный хеш разрешения на откат и редакцию маршрутизации перед применением отката.
- [ ] **После** отката проверить UUID и вход игроков, данные миров и плагинов, а также подключение. Зафиксировать недоступные или заменённые вручную модули.

Этот контрольный список создан на основе авторитетного отчёта и сам по себе не доказывает выполнения действий. Для приёмки Migration GA необходимы подписанные закрытые доказательства сквозных проверок (E2E) и независимая проверка работающих систем по всем трём эталонным классам.
`)
	return []byte(b.String()), nil
}

func exportManualWorklist(ctx context.Context, p Plan, token, output string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("Отсутствует токен серверной части для приёмочных проверок GA")
	}
	if err := checkBackendURL(p.Backend); err != nil {
		return err
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	endpoint := strings.TrimRight(p.Backend, "/") + "/api/v1/admin/migration-runs/" + url.PathEscape(p.RunID) + "/report"
	var report Report
	if err := getJSON(ctx, client, endpoint, token, &report); err != nil {
		return err
	}
	raw, err := renderManualWorklist(p, report)
	if err != nil {
		return err
	}
	return writePrivate(output, raw)
}
