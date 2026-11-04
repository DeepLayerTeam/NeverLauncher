-- Hot-reloadable, non-secret operations settings; compare-and-swap on current revision.
CREATE TABLE operational_config_current (
 id SMALLINT PRIMARY KEY CHECK (id=1), revision BIGINT NOT NULL CHECK (revision>=1),
 settings JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE operational_config_revisions (
 revision BIGINT PRIMARY KEY, settings JSONB NOT NULL,
 actor TEXT NOT NULL, reason TEXT NOT NULL,
 restored_from BIGINT REFERENCES operational_config_revisions(revision),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO operational_config_current(id,revision,settings) VALUES (1,1,'{"auditDefaultPageSize":25,"auditMaxPageSize":100,"auditLookbackDays":30,"auditExposeClientDetails":false,"jobsDefaultPageSize":25,"jobsMaxPageSize":100}'::jsonb);
INSERT INTO operational_config_revisions(revision,settings,actor,reason) SELECT revision,settings,'system','initial defaults' FROM operational_config_current;
ALTER TABLE audit_events ADD COLUMN correlation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN reason_code TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN job_id TEXT NOT NULL DEFAULT '';
CREATE INDEX audit_events_filter_02111 ON audit_events (created_at DESC,id DESC);
CREATE INDEX audit_events_correlation_02111 ON audit_events(correlation_id) WHERE correlation_id<>'';
