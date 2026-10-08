-- NeverLauncher 0.21.0: NeverExtensions GA контракт + 0.20 -> 0.21 обновление маркер.
-- Существующий подписанный 0.20 пакеты оставаться неизменяемый и сохранять API='3.7'; среда выполнения сопоставляет
-- тот value к Расширение API v1. Новый публикация являются применять как API='1.0'.

CREATE TABLE IF NOT EXISTS extension_ga_contract (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    package_format_version TEXT NOT NULL CHECK (package_format_version='1.0'),
    manifest_schema_version TEXT NOT NULL CHECK (manifest_schema_version='2.0'),
    host_protocol_version TEXT NOT NULL CHECK (host_protocol_version='1.0'),
    extension_api_version TEXT NOT NULL CHECK (extension_api_version='1.0'),
    legacy_api_aliases JSONB NOT NULL DEFAULT '["3.7"]'::jsonb CHECK (jsonb_typeof(legacy_api_aliases)='array'),
    upgraded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO extension_ga_contract(singleton,package_format_version,manifest_schema_version,host_protocol_version,extension_api_version,legacy_api_aliases)
VALUES(TRUE,'1.0','2.0','1.0','1.0','["3.7"]'::jsonb)
ON CONFLICT(singleton) DO UPDATE SET
    package_format_version=EXCLUDED.package_format_version,
    manifest_schema_version=EXCLUDED.manifest_schema_version,
    host_protocol_version=EXCLUDED.host_protocol_version,
    extension_api_version=EXCLUDED.extension_api_version,
    legacy_api_aliases=EXCLUDED.legacy_api_aliases,
    upgraded_at=now();

DO $$
DECLARE unsupported_count BIGINT;
BEGIN
    SELECT count(*) INTO unsupported_count
      FROM extension_versions
     WHERE btrim(api) NOT IN ('1.0','1.0.0','3.7','3.7.0','v1','v1.0','v1.0.0');
    IF unsupported_count > 0 THEN
        RAISE EXCEPTION 'NeverExtensions 0.21.0 upgrade blocked: % extension_versions rows use unsupported API values', unsupported_count;
    END IF;
END;
$$;

COMMENT ON TABLE extension_ga_contract IS 'Frozen NeverExtensions GA contract and 0.20 compatibility alias state (0.21.0).';
