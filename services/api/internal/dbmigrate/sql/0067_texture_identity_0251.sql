-- 0.25.1: canonical Minecraft identity, content metadata, scoped selections and immutable audit.
-- Existing Minecraft UUIDs and the legacy ServerBridge table remain unchanged.
CREATE TABLE texture_identities (
    realm TEXT NOT NULL CHECK (realm IN ('local-project','official-minecraft')),
    profile_uuid TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile_name TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('local-profile','verified-official')),
    local_profile_uuid TEXT REFERENCES minecraft_profiles(uuid) ON DELETE CASCADE,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (realm,profile_uuid),
    UNIQUE (realm,profile_uuid,user_id),
    CONSTRAINT texture_identity_origin CHECK (
       (realm='local-project' AND origin='local-profile' AND local_profile_uuid=profile_uuid AND verified_at IS NULL)
       OR (realm='official-minecraft' AND origin='verified-official' AND local_profile_uuid IS NULL AND verified_at IS NOT NULL)
    )
);
CREATE INDEX idx_texture_identities_owner ON texture_identities(user_id,realm);

CREATE TABLE texture_blobs (
    digest TEXT PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
    byte_size BIGINT NOT NULL CHECK (byte_size > 0),
    width INTEGER NOT NULL CHECK (width > 0 AND width <= 8192),
    height INTEGER NOT NULL CHECK (height > 0 AND height <= 8192),
    media_type TEXT NOT NULL DEFAULT 'image/png' CHECK (media_type='image/png'),
    storage_driver TEXT NOT NULL CHECK (storage_driver IN ('local','s3')),
    object_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('staging','verified','quarantined')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ,
    UNIQUE(storage_driver,object_key),
    CHECK ((status='verified')=(verified_at IS NOT NULL))
);
CREATE INDEX idx_texture_blobs_lifecycle ON texture_blobs(status,created_at);

CREATE TABLE texture_assignments (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    realm TEXT NOT NULL,
    profile_uuid TEXT NOT NULL,
    user_id TEXT NOT NULL,
    project_id TEXT NOT NULL DEFAULT '', -- empty means global project-independent selection
    launcher_profile_id TEXT NOT NULL DEFAULT '', -- NEVER a Minecraft profile UUID
    kind TEXT NOT NULL CHECK (kind IN ('skin','cape')),
    blob_digest TEXT REFERENCES texture_blobs(digest) ON DELETE RESTRICT,
    external_url TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL CHECK (source IN ('managed-upload','imported','remote-reference','official')),
    model TEXT NOT NULL DEFAULT 'classic' CHECK (model IN ('classic','slim')),
    visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','private','unlisted')),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    active BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(realm,profile_uuid,user_id) REFERENCES texture_identities(realm,profile_uuid,user_id) ON DELETE CASCADE,
    UNIQUE(realm,profile_uuid,project_id,kind),
    CHECK ((blob_digest IS NULL) <> (external_url='')),
    CHECK (source!='official' OR realm='official-minecraft'),
    CHECK (kind='skin' OR model='classic')
);
CREATE INDEX idx_texture_assignments_owner ON texture_assignments(user_id,realm,project_id);
CREATE INDEX idx_texture_assignments_blob ON texture_assignments(blob_digest) WHERE blob_digest IS NOT NULL;

CREATE TABLE texture_assignment_revisions (
    assignment_id BIGINT NOT NULL REFERENCES texture_assignments(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK(revision >= 1),
    snapshot JSONB NOT NULL,
    actor_user_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('legacy-import','select','model-change','visibility-change','reset')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(assignment_id,revision)
);
CREATE INDEX idx_texture_revisions_actor ON texture_assignment_revisions(actor_user_id,created_at DESC);

-- Configurable per-project limits/default references. Policy mutations/grant UI
-- arrive in T05; data is already keyed independently from Minecraft UUID.
CREATE TABLE texture_project_policies (
    project_id TEXT PRIMARY KEY,
    default_skin_digest TEXT REFERENCES texture_blobs(digest) ON DELETE RESTRICT,
    default_cape_digest TEXT REFERENCES texture_blobs(digest) ON DELETE RESTRICT,
    allow_player_skins BOOLEAN NOT NULL DEFAULT true,
    allow_player_capes BOOLEAN NOT NULL DEFAULT false,
    max_bytes_per_player BIGINT NOT NULL DEFAULT 10485760 CHECK (max_bytes_per_player BETWEEN 1024 AND 1073741824),
    max_blobs_per_player INTEGER NOT NULL DEFAULT 20 CHECK (max_blobs_per_player BETWEEN 1 AND 10000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE texture_cape_grants (
    project_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted BOOLEAN NOT NULL,
    actor_user_id TEXT NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(project_id,user_id)
);

CREATE TABLE texture_legacy_aliases (
    legacy_uuid TEXT PRIMARY KEY,
    realm TEXT NOT NULL DEFAULT 'local-project',
    profile_uuid TEXT NOT NULL,
    user_id TEXT NOT NULL,
    mapping TEXT NOT NULL CHECK(mapping IN ('exact','user-derived-v2')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(realm,profile_uuid,user_id) REFERENCES texture_identities(realm,profile_uuid,user_id) ON DELETE CASCADE
);
CREATE INDEX idx_texture_alias_profile ON texture_legacy_aliases(profile_uuid);

CREATE TABLE texture_legacy_unmatched (
    legacy_uuid TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    skin_url TEXT NOT NULL,
    cape_url TEXT NOT NULL,
    model TEXT NOT NULL,
    original_updated_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL DEFAULT 'no-proven-canonical-minecraft-identity',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- sha256(bytea) is built-in in PostgreSQL 14+; no pgcrypto extension required.
INSERT INTO texture_identities(realm,profile_uuid,user_id,profile_name,origin,local_profile_uuid)
SELECT 'local-project',uuid,user_id,name,'local-profile',uuid FROM minecraft_profiles
ON CONFLICT(realm,profile_uuid) DO NOTHING;

INSERT INTO texture_legacy_aliases(legacy_uuid,profile_uuid,user_id,mapping)
SELECT lower(p.uuid),p.uuid,p.user_id,'exact' FROM minecraft_profiles p
ON CONFLICT(legacy_uuid) DO NOTHING;
INSERT INTO texture_legacy_aliases(legacy_uuid,profile_uuid,user_id,mapping)
SELECT substring(h FROM 1 FOR 8)||'-'||substring(h FROM 9 FOR 4)||'-'||substring(h FROM 13 FOR 4)||'-'||substring(h FROM 17 FOR 4)||'-'||substring(h FROM 21 FOR 12),uuid,user_id,'user-derived-v2'
FROM (SELECT uuid,user_id,encode(sha256(convert_to('neverlauncher-player:'||user_id,'UTF8')),'hex') h FROM minecraft_profiles) derived
ON CONFLICT(legacy_uuid) DO NOTHING;

INSERT INTO texture_assignments(realm,profile_uuid,user_id,kind,external_url,source,model,visibility,updated_at)
SELECT a.realm,a.profile_uuid,a.user_id, k.kind,k.url,'remote-reference',
    CASE WHEN k.kind='skin' THEN CASE WHEN t.model='slim' THEN 'slim' ELSE 'classic' END ELSE 'classic' END,
    'public',t.updated_at
FROM server_bridge_textures_v2 t JOIN texture_legacy_aliases a ON lower(t.player_uuid)=a.legacy_uuid
CROSS JOIN LATERAL (VALUES ('skin',t.skin_url),('cape',t.cape_url)) k(kind,url)
WHERE k.url <> ''
ON CONFLICT(realm,profile_uuid,project_id,kind) DO NOTHING;

INSERT INTO texture_assignment_revisions(assignment_id,revision,snapshot,actor_user_id,reason,event)
SELECT id,revision,jsonb_build_object('source',source,'kind',kind,'externalUrl',external_url,'model',model,'visibility',visibility,'active',active,'projectId',project_id,'blobDigest',blob_digest),user_id,'0.25.0 ServerBridge URL migration','legacy-import'
FROM texture_assignments
ON CONFLICT(assignment_id,revision) DO NOTHING;

INSERT INTO texture_legacy_unmatched(legacy_uuid,username,skin_url,cape_url,model,original_updated_at)
SELECT t.player_uuid,t.username,t.skin_url,t.cape_url,t.model,t.updated_at
FROM server_bridge_textures_v2 t LEFT JOIN texture_legacy_aliases a ON lower(t.player_uuid)=a.legacy_uuid
WHERE a.legacy_uuid IS NULL
ON CONFLICT(legacy_uuid) DO NOTHING;
