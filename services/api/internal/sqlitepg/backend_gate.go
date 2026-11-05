package sqlitepg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RejectUnapprovedBackend0475 не даёт API незаметно активировать
// офлайн-импорт. В версии 0.47.5 отсутствует квитанция совпадения состояний HTTP/Coordinator,
// поэтому даже проверенная квитанция Core/файлов НЕ разрешает производственное переключение.
// Проверяется до запуска API, воркеров и слушателей запросов.
// Обычные установки PostgreSQL без импорта SQLite не затрагиваются.
func RejectUnapprovedBackend0475(ctx context.Context, dsn string) error {
	if strings.TrimSpace(dsn) == "" {
		return errors.New("Необходимо указать DSN PostgreSQL")
	}
	pg, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("Подключение к PostgreSQL для контрольной проверки Backend завершилось ошибкой (учётные данные скрыты): %w", err)
	}
	defer pg.Close(context.Background())
	for _, name := range []string{"public.sqlite_live_receipts_0473", Schema + ".migration_receipt"} {
		var present bool
		if err := pg.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&present); err != nil {
			return fmt.Errorf("Не удалось проверить состояние переключения: %w", err)
		}
		if !present {
			continue
		}
		var count int64
		// Идентификаторы заданы в этом исходном файле и никогда не подставляются из
		// входных HTTP-данных или управляемой пользователем квитанции PostgreSQL.
		switch name {
		case "public.sqlite_live_receipts_0473":
			err = pg.QueryRow(ctx, `SELECT count(*) FROM public.sqlite_live_receipts_0473`).Scan(&count)
		default:
			err = pg.QueryRow(ctx, `SELECT count(*) FROM `+qualified("migration_receipt")).Scan(&count)
		}
		if err != nil {
			return fmt.Errorf("Не удалось проверить подтверждения переключения: %w", err)
		}
		if count != 0 {
			return errors.New("Обнаружен импорт SQLite без подтверждённого разрешения переключения HTTP/Coordinator; запуск Backend запрещён (0.47.5)")
		}
	}
	return nil
}
