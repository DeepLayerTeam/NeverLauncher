-- NeverLauncher 0.21.1 — Основа авторизации и идентичность границы.
-- проект_пользователь_роли становится авторитетный участие в проекте хранилище. устаревший
-- пользователи.проект_роли JSON остаётся совместимость projection только.

INSERT INTO roles(id,name,description,permissions) VALUES
 ('operator','Оператор','Работа с профилями, пакетами и файлами без финальной публикации','["project:read","project:write","release:prepare","file:write","diagnostics:read"]'::jsonb),
 ('support','Поддержка','Чтение проекта, диагностика и аудит без права изменения','["project:read","diagnostics:read","audit:read"]'::jsonb)
ON CONFLICT(id) DO NOTHING;

-- Никогда без уведомления widen или reinterpret pre-существующий роль с один 
-- канонический 0.21.1 ID. collision должен быть разрешённый явно через оператор.
DO $$
DECLARE broken BIGINT;
BEGIN
    SELECT count(*) INTO broken
    FROM roles r
    JOIN (VALUES
      ('operator'::text, '["project:read","project:write","release:prepare","file:write","diagnostics:read"]'::jsonb),
      ('support'::text, '["project:read","diagnostics:read","audit:read"]'::jsonb)
    ) expected(id, permissions) ON expected.id=r.id
    WHERE NOT (r.permissions @> expected.permissions
               AND r.permissions <@ expected.permissions
               AND jsonb_array_length(r.permissions)=jsonb_array_length(expected.permissions));
    IF broken <> 0 THEN
        RAISE EXCEPTION '0.21.1 migration refused: canonical operator/support role id already exists with different permissions';
    END IF;
END $$;

DO $$
DECLARE broken BIGINT;
BEGIN
    SELECT count(*) INTO broken FROM users u WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.id=u.role_id);
    IF broken <> 0 THEN
        RAISE EXCEPTION '0.21.1 migration refused: % users reference an unknown global role', broken;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='users_global_role_fk') THEN
        ALTER TABLE users ADD CONSTRAINT users_global_role_fk FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE RESTRICT;
    END IF;
END $$;

-- Отклонять конкретный устаревший участие тот не может быть представленный безопасно вместо этого 
-- без уведомления сопоставление их к broader разрешения.
DO $$
DECLARE broken BIGINT;
BEGIN
    SELECT count(*) INTO broken
    FROM users u
    CROSS JOIN LATERAL jsonb_each_text(COALESCE(u.project_roles,'{}'::jsonb)) e(project_id, role_id)
    WHERE e.project_id <> '*'
      AND (NOT EXISTS (SELECT 1 FROM projects p WHERE p.id=e.project_id)
           OR NOT EXISTS (SELECT 1 FROM roles r WHERE r.id=e.role_id));
    IF broken <> 0 THEN
        RAISE EXCEPTION '0.21.1 migration refused: % users.project_roles memberships reference an unknown project or role', broken;
    END IF;

    SELECT count(*) INTO broken
    FROM project_user_roles pur
    WHERE pur.project_id='*'
       OR NOT EXISTS (SELECT 1 FROM projects p WHERE p.id=pur.project_id)
       OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id=pur.user_id)
       OR NOT EXISTS (SELECT 1 FROM roles r WHERE r.id=pur.role_id);
    IF broken <> 0 THEN
        RAISE EXCEPTION '0.21.1 migration refused: % project_user_roles rows are invalid', broken;
    END IF;
END $$;

-- Импорт только конкретный участие. Исторический "*" участие являются намеренно
-- не преобразован: экземпляр-wide authority comes exclusively из пользователи.роль_ID.
INSERT INTO project_user_roles(project_id,user_id,role_id,created_at,updated_at)
SELECT e.project_id, u.id, e.role_id, COALESCE(u.created_at,now()), now()
FROM users u
CROSS JOIN LATERAL jsonb_each_text(COALESCE(u.project_roles,'{}'::jsonb)) e(project_id, role_id)
WHERE e.project_id <> '*'
ON CONFLICT(project_id,user_id) DO UPDATE SET role_id=EXCLUDED.role_id, updated_at=now();

CREATE INDEX IF NOT EXISTS idx_project_user_roles_user ON project_user_roles(user_id,project_id);
CREATE INDEX IF NOT EXISTS idx_project_user_roles_role ON project_user_roles(role_id);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='project_user_roles_project_fk') THEN
        ALTER TABLE project_user_roles
            ADD CONSTRAINT project_user_roles_project_fk FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='project_user_roles_user_fk') THEN
        ALTER TABLE project_user_roles
            ADD CONSTRAINT project_user_roles_user_fk FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='project_user_roles_role_fk') THEN
        ALTER TABLE project_user_roles
            ADD CONSTRAINT project_user_roles_role_fk FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='project_user_roles_project_not_wildcard') THEN
        ALTER TABLE project_user_roles
            ADD CONSTRAINT project_user_roles_project_not_wildcard CHECK(project_id <> '*');
    END IF;
END $$;

-- Сохранять старый JSON column synchronized как совместимость projection. Это нет дольше
-- содержит wildcard/global authority.
UPDATE users u
SET project_roles = COALESCE((
    SELECT jsonb_object_agg(pur.project_id,pur.role_id ORDER BY pur.project_id)
    FROM project_user_roles pur WHERE pur.user_id=u.id
), '{}'::jsonb), updated_at=now();

CREATE OR REPLACE FUNCTION nl_sync_user_project_roles_0211() RETURNS trigger AS $$
DECLARE affected_user TEXT;
BEGIN
    affected_user := COALESCE(NEW.user_id, OLD.user_id);
    UPDATE users u
       SET project_roles = COALESCE((
           SELECT jsonb_object_agg(pur.project_id,pur.role_id ORDER BY pur.project_id)
             FROM project_user_roles pur WHERE pur.user_id=affected_user
       ), '{}'::jsonb), updated_at=now()
     WHERE u.id=affected_user;
    RETURN COALESCE(NEW, OLD);
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_project_user_roles_projection_0211 ON project_user_roles;
CREATE TRIGGER trg_project_user_roles_projection_0211
AFTER INSERT OR UPDATE OR DELETE ON project_user_roles
FOR EACH ROW EXECUTE FUNCTION nl_sync_user_project_roles_0211();

-- GameProfile идентичность метаданные. Существующий UUIDs оставаться untouched; они являются marked как
-- устаревший-производный. Новый профили использовать сохранённый random UUIDv4 идентичности независимый
-- из Никогда пользователь ID.
ALTER TABLE IF EXISTS minecraft_profiles ADD COLUMN IF NOT EXISTS issuer TEXT NOT NULL DEFAULT 'neverlauncher';
ALTER TABLE IF EXISTS minecraft_profiles ADD COLUMN IF NOT EXISTS realm TEXT NOT NULL DEFAULT 'local';
ALTER TABLE IF EXISTS minecraft_profiles ADD COLUMN IF NOT EXISTS subject TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS minecraft_profiles ADD COLUMN IF NOT EXISTS identity_version TEXT NOT NULL DEFAULT 'legacy-user-derived-v2';
UPDATE minecraft_profiles
SET issuer=COALESCE(NULLIF(issuer,''),'neverlauncher'),
    realm=COALESCE(NULLIF(realm,''),'local'),
    subject=COALESCE(NULLIF(subject,''),uuid),
    identity_version=COALESCE(NULLIF(identity_version,''),'legacy-user-derived-v2');
CREATE UNIQUE INDEX IF NOT EXISTS idx_minecraft_profiles_issuer_realm_subject
    ON minecraft_profiles(issuer,realm,subject);
