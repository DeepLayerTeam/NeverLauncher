-- Launcher 0.10.1: механизм совместимости, учитывающий платформу в метаданных релизных
-- файлов. Существующие строки остаются независимыми от платформы и неисполняемыми.
ALTER TABLE files ADD COLUMN IF NOT EXISTS executable BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE files ADD COLUMN IF NOT EXISTS target_os JSONB NOT NULL DEFAULT '[]'::jsonb;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'files' AND column_name = 'target_os'
    ) THEN
        UPDATE files SET target_os = '[]'::jsonb WHERE target_os IS NULL;
    END IF;
END $$;
