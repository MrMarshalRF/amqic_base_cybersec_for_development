-- Fresh, isolated database only. Run as migration administrator; never at app startup.
\set ON_ERROR_STOP on
BEGIN;
-- Exact synthetic database; adapt the identifier through reviewed migrations elsewhere.
REVOKE CREATE, TEMPORARY ON DATABASE postgres FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE ROLE app_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE tenant_alpha LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE tenant_beta LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
CREATE ROLE replay_service LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
GRANT CONNECT ON DATABASE postgres TO tenant_alpha, tenant_beta, replay_service;
CREATE SCHEMA app AUTHORIZATION app_owner;
CREATE SCHEMA replay AUTHORIZATION app_owner;
SET LOCAL ROLE app_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE app.contacts (
  id uuid NOT NULL,
  tenant_id text NOT NULL DEFAULT current_user,
  display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 256),
  private_ciphertext bytea,
  PRIMARY KEY (tenant_id, id)
);
ALTER TABLE app.contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.contacts FORCE ROW LEVEL SECURITY;
CREATE POLICY own_rows ON app.contacts TO tenant_alpha, tenant_beta
  USING (tenant_id = current_user) WITH CHECK (tenant_id = current_user);
GRANT USAGE ON SCHEMA app TO tenant_alpha, tenant_beta;
GRANT SELECT (id, tenant_id, display_name), INSERT (id, tenant_id, display_name),
  UPDATE (display_name) ON app.contacts TO tenant_alpha, tenant_beta;
GRANT DELETE ON app.contacts TO tenant_alpha, tenant_beta;

CREATE TABLE replay.allowed_keys (
  audience text NOT NULL, key_id text NOT NULL,
  PRIMARY KEY (audience, key_id)
);
CREATE TABLE replay.clock_guard (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  high_water timestamptz NOT NULL
);
INSERT INTO replay.clock_guard VALUES (true, clock_timestamp());
CREATE TABLE replay.used_nonces (
  audience text NOT NULL, key_id text NOT NULL, nonce text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (audience, key_id, nonce),
  FOREIGN KEY (audience, key_id) REFERENCES replay.allowed_keys
);
CREATE INDEX used_nonces_expiry ON replay.used_nonces (expires_at);
-- Fixed synthetic registry. Real registrations/revocations belong to migrations.
INSERT INTO replay.allowed_keys VALUES ('synthetic-api', 'synthetic-key-1');

CREATE FUNCTION replay.consume_nonce(p_audience text, p_key_id text, p_nonce text,
                                      p_issued_at timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s' AS $$
DECLARE previous_time timestamptz; server_time timestamptz; inserted integer;
BEGIN
  IF p_audience IS NULL OR p_key_id IS NULL OR p_nonce IS NULL OR p_issued_at IS NULL
     OR octet_length(p_audience) NOT BETWEEN 1 AND 128
     OR octet_length(p_key_id) NOT BETWEEN 1 AND 128
     OR p_nonce !~ '^[A-Za-z0-9_-]{22,128}$'
     OR NOT isfinite(p_issued_at) THEN RETURN false; END IF;
  IF NOT EXISTS (SELECT 1 FROM replay.allowed_keys
                 WHERE audience = p_audience AND key_id = p_key_id) THEN RETURN false; END IF;
  -- Serialize the authoritative time sample and claim. Sample AFTER acquiring lock.
  SELECT high_water INTO previous_time FROM replay.clock_guard
    WHERE singleton FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Replay clock guard missing; fail closed' USING ERRCODE = '55000';
  END IF;
  server_time := clock_timestamp();
  IF server_time < previous_time THEN
    RAISE EXCEPTION 'Replay clock moved backwards; fail closed' USING ERRCODE = '55000';
  END IF;
  UPDATE replay.clock_guard SET high_water = server_time WHERE singleton;
  IF p_issued_at < server_time - interval '30 seconds'
     OR p_issued_at > server_time + interval '30 seconds' THEN RETURN false; END IF;
  -- Retain beyond the entire last possible acceptance instant, not merely arrival+TTL.
  DELETE FROM replay.used_nonces WHERE expires_at < server_time;
  INSERT INTO replay.used_nonces VALUES
    (p_audience, p_key_id, p_nonce, p_issued_at + interval '31 seconds')
    ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  RETURN inserted = 1;
END $$;
REVOKE ALL ON FUNCTION replay.consume_nonce(text,text,text,timestamptz) FROM PUBLIC;
GRANT USAGE ON SCHEMA replay TO replay_service;
GRANT EXECUTE ON FUNCTION replay.consume_nonce(text,text,text,timestamptz) TO replay_service;
COMMIT;
