-- Launcher 0.47.3: retain exact ordered file mirror URLs alongside
-- immutable release manifest JSON. Never overwrite historical migrations.
ALTER TABLE files ADD COLUMN mirrors JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK(jsonb_typeof(mirrors)='array');
