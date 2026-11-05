// Автономная миграция Gravit TextureProvider только для оператора. Нет
// HTTP-маршрута, учётных данных авторизации из пользовательского ввода и удалённых
// обращений по file_url.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gitflic.ru/skif4er/launcher/services/api/internal/repository"
	"gitflic.ru/skif4er/launcher/services/api/internal/storage"
	"gitflic.ru/skif4er/launcher/services/api/internal/texturegravit"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gravit-textures-import:", err)
		os.Exit(1)
	}
}
func getenv(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func makeStorage(driver, path, endpoint, bucket, region, key, secret, pathStyle string) (storage.Storage, error) {
	switch driver {
	case "local":
		if path == "" {
			return nil, errors.New("Требуется: путь к локальному хранилищу")
		}
		return storage.NewLocalStorage(path), nil
	case "s3":
		ps, err := strconv.ParseBool(pathStyle)
		if err != nil {
			return nil, err
		}
		return storage.NewS3Storage(storage.S3Config{Endpoint: endpoint, Bucket: bucket, Region: region, AccessKey: key, SecretKey: secret, PathStyle: ps})
	default:
		return nil, errors.New("Не поддерживается: драйвер хранилища")
	}
}
func isApprovedTexturePlan0445(d string) bool {
	if len(d) != 64 {
		return false
	}
	for _, c := range d {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func texturePreviewClean0445(report texturegravit.Report) bool {
	if len(report.Rows) == 0 {
		return false
	}
	for status, count := range report.Counts {
		if count > 0 && status != "validated-dry-run" && status != "already-imported" {
			return false
		}
	}
	return true
}

func run() error {
	sourceID := flag.String("source-id", "", "Постоянный идентификатор старой установки (обязательно)")
	sourceJSON := flag.String("source-json", "", "Автономный JSON-экспорт таблицы textures из TextureProvider")
	sourceDSN := flag.String("source-dsn", "", "DSN исходной базы PostgreSQL (вместо source-json)")
	sourceRoot := flag.String("source-root", "", "Доверенный локальный каталог исходных PNG")
	sourceS3 := flag.Bool("source-s3", false, "Читать объекты из отдельно настроенного старого бакета S3")
	sourceTemplate := flag.String("source-template", "%kind%/%hash%.png", "Шаблон ключа объекта, например skins/%hash%.png или %hash%")
	mappingFile := flag.String("mapping", "", "JSON-массив source_uuid,target_uuid; отсутствующие идентификаторы пропускаются")
	reportFile := flag.String("report", "", "Обязательный путь к выходному JSON-отчёту")
	replace := flag.Bool("replace", false, "Явно заменить существующую привязку текстуры Launcher")
	dryRun := flag.Bool("dry-run", false, "Проверить исходные PNG и идентификаторы без сохранения")
	approved := flag.String("approved-plan-sha256", "", "Для реального импорта требуется planSha256 из проверенного отчёта пробного запуска")
	flag.Parse()
	if *reportFile == "" || *sourceID == "" {
		return errors.New("Требуются параметры --report и --source-id")
	}
	if (*sourceJSON == "") == (*sourceDSN == "") {
		return errors.New("Выберите ровно один параметр: --source-json или --source-dsn")
	}
	if (*sourceRoot != "") == *sourceS3 {
		return errors.New("Выберите ровно один параметр: --source-root или --source-s3")
	}
	if *sourceRoot != "" {
		if _, err := os.Stat(*sourceRoot); err != nil {
			return err
		}
	}
	destDSN := strings.TrimSpace(os.Getenv("LAUNCHER_DATABASE_DSN"))
	if destDSN == "" {
		return errors.New("Требуется: LAUNCHER_DATABASE_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	repo := repository.NewSQLRepository("pgx", destDSN, "").(*repository.SQLRepository)
	if err := repo.Health(ctx); err != nil {
		return fmt.Errorf("Ошибка целевой базы данных: %w", err)
	}
	var sourceRows []texturegravit.SourceRow
	var err error
	if *sourceJSON != "" {
		fi, statErr := os.Stat(*sourceJSON)
		if statErr != nil {
			return statErr
		}
		if fi.Size() > 32<<20 {
			return errors.New("Размер исходного экспорта превышает 32 МиБ")
		}
		b, readErr := os.ReadFile(*sourceJSON)
		if readErr != nil {
			return readErr
		}
		sourceRows, err = texturegravit.LoadJSON(b)
	} else {
		db, openErr := sql.Open("pgx", *sourceDSN)
		if openErr != nil {
			return openErr
		}
		defer db.Close()
		db.SetMaxOpenConns(2)
		if err = db.PingContext(ctx); err != nil {
			return fmt.Errorf("Ошибка исходной PostgreSQL: %w", err)
		}
		sourceRows, err = texturegravit.ReadPostgres(ctx, db)
	}
	if err != nil {
		return err
	}
	mapping := map[string]string{}
	if *mappingFile != "" {
		b, e := os.ReadFile(*mappingFile)
		if e != nil {
			return e
		}
		mapping, e = texturegravit.LoadMappings(b)
		if e != nil {
			return e
		}
	}
	dst, e := makeStorage(getenv("LAUNCHER_STORAGE_DRIVER", "local"), getenv("LAUNCHER_STORAGE_LOCAL_PATH", "./data/storage"), os.Getenv("LAUNCHER_STORAGE_S3_ENDPOINT"), os.Getenv("LAUNCHER_STORAGE_S3_BUCKET"), os.Getenv("LAUNCHER_STORAGE_S3_REGION"), os.Getenv("LAUNCHER_STORAGE_S3_ACCESS_KEY"), os.Getenv("LAUNCHER_STORAGE_S3_SECRET_KEY"), getenv("LAUNCHER_STORAGE_S3_PATH_STYLE", "true"))
	if e != nil {
		return e
	}
	if !*dryRun {
		if e = dst.Health(ctx); e != nil {
			return fmt.Errorf("Ошибка целевого хранилища: %w", e)
		}
	}
	var source texturegravit.Source
	if *sourceS3 {
		legacyStore, e := makeStorage("s3", "", os.Getenv("GRAVIT_S3_ENDPOINT"), os.Getenv("GRAVIT_S3_BUCKET"), os.Getenv("GRAVIT_S3_REGION"), os.Getenv("GRAVIT_S3_ACCESS_KEY"), os.Getenv("GRAVIT_S3_SECRET_KEY"), getenv("GRAVIT_S3_PATH_STYLE", "true"))
		if e != nil {
			return e
		}
		source = texturegravit.S3Source{Store: legacyStore.(*storage.S3Storage)}
	} else {
		source = texturegravit.LocalSource{Root: *sourceRoot}
	}
	runner := texturegravit.Runner{Database: repo, Source: source, Destination: dst, SourceID: *sourceID, ObjectTemplate: *sourceTemplate, Mapping: mapping, Replace: *replace, DryRun: true}
	// Всегда выполняйте новую проверку байтов/UUID только на чтение до любых живых
	// записей. Она гарантирует пригодность всех исходных изображений и целевых
	// идентичностей до изменения первого выбора. При изменении плана нужно повторное
	// одобрение.
	report, runErr := runner.Run(ctx, sourceRows)
	if runErr == nil && !*dryRun {
		if !isApprovedTexturePlan0445(*approved) || report.PlanSHA256 != *approved {
			runErr = errors.New("Для импорта в действующую систему укажите --approved-plan-sha256, совпадающий с текущим проверенным отчётом пробного запуска")
		} else if !texturePreviewClean0445(report) {
			runErr = errors.New("Предварительная проверка источника не завершена; устраните ошибки, несопоставленные и неоднозначные текстуры до импорта в рабочую систему")
		} else {
			runner.DryRun = false
			report, runErr = runner.Run(ctx, sourceRows)
		}
	}
	// Сохраняйте причину неудачной предварительной проверки в отчёте 0600, даже
	// если оператор предоставил устаревшее одобрение или источник изменился до
	// живого импорта.
	if runErr != nil && report.FatalError == "" {
		report.FatalError = runErr.Error()
	}
	// Записывайте отчёт, даже если отмена контекста прервала импорт.
	encoded, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		return e
	}
	reportPath, e := filepath.Abs(*reportFile)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(reportPath), 0700); e != nil {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(reportPath), ".gravit-report-*")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if e = tmp.Chmod(0600); e != nil {
		return e
	}
	if _, e = tmp.Write(append(encoded, '\n')); e != nil {
		return e
	}
	if e = tmp.Sync(); e != nil {
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp.Name(), reportPath); e != nil {
		return e
	}
	fmt.Printf("Gravit texture migration: %d rows; results=%v; report=%s\n", len(report.Rows), report.Counts, reportPath)
	if runErr != nil {
		return runErr
	}
	if report.Counts["blocked"] > 0 || report.Counts["unmatched"] > 0 || report.Counts["quarantined"] > 0 || report.Counts["skipped-existing"] > 0 {
		return errors.New("Миграция не завершена: отчёт содержит заблокированные, несопоставленные, изолированные или пропущенные существующие записи")
	}
	return nil
}
