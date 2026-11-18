BEGIN;
CREATE SCHEMA amqic_quota;

CREATE TABLE amqic_quota.tenant_state (
    tenant text PRIMARY KEY CHECK (tenant ~ '^[a-zA-Z0-9_-]{1,80}$'),
    generation text NOT NULL CHECK (generation ~ '^[a-zA-Z0-9_-]{1,80}$'),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
    window_ms integer NOT NULL CHECK (window_ms BETWEEN 1000 AND 3600000),
    normal_cap integer NOT NULL CHECK (normal_cap BETWEEN 1 AND 1000),
    elevated_cap integer NOT NULL CHECK (elevated_cap BETWEEN 0 AND normal_cap),
    last_ms bigint NOT NULL DEFAULT 0 CHECK (last_ms >= 0),
    window_id bigint NOT NULL DEFAULT 0 CHECK (window_id >= 0),
    elevated boolean NOT NULL DEFAULT false,
    used integer NOT NULL DEFAULT 0 CHECK (used BETWEEN 0 AND 1000),
    operations jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(operations) = 'object')
);
REVOKE ALL ON SCHEMA amqic_quota FROM PUBLIC;

CREATE FUNCTION amqic_quota.admit(
    p_tenant text, p_generation text, p_digest text, p_operation text,
    p_binding text, p_window bigint, p_risk text
) RETURNS text
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    s amqic_quota.tenant_state%ROWTYPE;
    now_ms bigint;
    current_window bigint;
    prior_binding text;
    cap integer;
    decision text;
BEGIN
    IF (p_tenant ~ '^[a-zA-Z0-9_-]{1,80}$' AND p_generation ~ '^[a-zA-Z0-9_-]{1,80}$'
        AND p_digest ~ '^[a-f0-9]{64}$' AND p_operation ~ '^[a-zA-Z0-9_-]{1,80}$'
        AND p_binding ~ '^[a-f0-9]{64}$' AND p_window BETWEEN 0 AND 10000000000
        AND p_risk IN ('normal','elevated')) IS NOT TRUE THEN
        RETURN 'invalid_request';
    END IF;

    SELECT * INTO s FROM amqic_quota.tenant_state
    WHERE tenant = p_tenant FOR UPDATE;
    IF NOT FOUND THEN RETURN 'unprovisioned'; END IF;
    IF s.generation <> p_generation OR s.policy_digest <> p_digest THEN
        RETURN 'policy_mismatch';
    END IF;

    IF s.used > s.normal_cap OR
       (SELECT count(*) FROM jsonb_each(s.operations)) <> s.used OR
       EXISTS (SELECT 1 FROM jsonb_each(s.operations) AS o(id, binding)
               WHERE id !~ '^[a-zA-Z0-9_-]{1,80}$' OR jsonb_typeof(binding) <> 'string'
                     OR (binding #>> '{}') !~ '^[a-f0-9]{64}$') THEN
        RETURN 'invalid_state';
    END IF;

    now_ms := floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
    IF now_ms < s.last_ms THEN RETURN 'clock_rollback'; END IF;
    current_window := now_ms / s.window_ms;
    IF current_window <> p_window THEN RETURN 'window_changed'; END IF;

    IF current_window <> s.window_id THEN
        s.operations := '{}'::jsonb;
        s.used := 0;
        s.elevated := false;
    END IF;
    prior_binding := s.operations ->> p_operation;
    IF prior_binding IS NOT NULL THEN
        RETURN CASE WHEN prior_binding = p_binding THEN 'duplicate' ELSE 'conflict' END;
    END IF;

    s.elevated := s.elevated OR p_risk = 'elevated';
    cap := CASE WHEN s.elevated THEN s.elevated_cap ELSE s.normal_cap END;
    IF s.used < cap THEN
        s.used := s.used + 1;
        s.operations := s.operations || jsonb_build_object(p_operation, p_binding);
        decision := 'granted';
    ELSE
        decision := 'rate_limited';
    END IF;
    UPDATE amqic_quota.tenant_state SET last_ms = now_ms, window_id = current_window,
        elevated = s.elevated, used = s.used, operations = s.operations
    WHERE tenant = p_tenant;
    RETURN decision;
END;
$function$;
REVOKE ALL ON FUNCTION amqic_quota.admit(text,text,text,text,text,bigint,text) FROM PUBLIC;
COMMIT;
