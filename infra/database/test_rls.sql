\set ON_ERROR_STOP on
-- Administrator harness ONLY. Dropping session authorization tests real role boundaries.
INSERT INTO app.contacts VALUES
 ('00000000-0000-0000-0000-000000000001','tenant_alpha','Alpha',decode('aa','hex')),
 ('00000000-0000-0000-0000-000000000002','tenant_beta','Beta',decode('bb','hex'));
SET SESSION AUTHORIZATION tenant_alpha;
DO $$ BEGIN
 IF (SELECT count(id) FROM app.contacts) <> 1 THEN RAISE EXCEPTION 'row leak'; END IF;
 IF EXISTS (SELECT id FROM app.contacts WHERE tenant_id='tenant_beta') THEN RAISE EXCEPTION 'cross read'; END IF;
 UPDATE app.contacts SET display_name='forbidden' WHERE tenant_id='tenant_beta';
 IF FOUND THEN RAISE EXCEPTION 'cross update'; END IF;
 DELETE FROM app.contacts WHERE tenant_id='tenant_beta';
 IF FOUND THEN RAISE EXCEPTION 'cross delete'; END IF;
 BEGIN INSERT INTO app.contacts (id,tenant_id,display_name) VALUES
  ('00000000-0000-0000-0000-000000000003','tenant_beta','forbidden');
  RAISE EXCEPTION 'cross insert'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM private_ciphertext FROM app.contacts;
  RAISE EXCEPTION 'private column'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM * FROM app.contacts;
  RAISE EXCEPTION 'star selection'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN UPDATE app.contacts SET tenant_id='tenant_beta';
  RAISE EXCEPTION 'tenant mutation'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN SET ROLE tenant_beta;
  RAISE EXCEPTION 'role escape'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN SET ROLE app_owner;
  RAISE EXCEPTION 'owner escape'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN SET ROLE replay_service;
  RAISE EXCEPTION 'replay escape'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN TRUNCATE app.contacts;
  RAISE EXCEPTION 'truncate'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN CREATE TABLE app.unauthorized(id int);
  RAISE EXCEPTION 'DDL'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM replay.consume_nonce('synthetic-api','synthetic-key-1',repeat('a',22),clock_timestamp());
  RAISE EXCEPTION 'tenant replay'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
-- A spoofed custom GUC has no authority in this policy.
SET app.tenant_id = 'tenant_beta';
PREPARE find_contact(text) AS SELECT id,tenant_id,display_name FROM app.contacts WHERE display_name=$1;
EXECUTE find_contact(''' OR true; DROP TABLE app.contacts; --');
DEALLOCATE find_contact;
INSERT INTO app.contacts(id,display_name) VALUES('00000000-0000-0000-0000-000000000004','Allowed');
-- Foreign row IDs cannot be used as an existence oracle through uniqueness errors.
INSERT INTO app.contacts(id,display_name) VALUES('00000000-0000-0000-0000-000000000002','Independent ID');
DELETE FROM app.contacts WHERE id='00000000-0000-0000-0000-000000000002';
UPDATE app.contacts SET display_name='Allowed update' WHERE id='00000000-0000-0000-0000-000000000004';
DO $$ BEGIN
 IF (SELECT count(id) FROM app.contacts WHERE tenant_id=current_user) <> 2 THEN RAISE EXCEPTION 'positive CRUD/GUC'; END IF;
END $$;
DELETE FROM app.contacts WHERE id='00000000-0000-0000-0000-000000000004';
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION tenant_beta;
DO $$ BEGIN
 IF (SELECT count(id) FROM app.contacts) <> 1 THEN RAISE EXCEPTION 'beta leak'; END IF;
END $$;
RESET SESSION AUTHORIZATION;
SET ROLE app_owner;
DO $$ BEGIN
 IF (SELECT count(*) FROM app.contacts) <> 0 THEN RAISE EXCEPTION 'owner FORCE bypass'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('tenant_alpha','tenant_beta','replay_service')
   AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolinherit)) THEN RAISE EXCEPTION 'role attributes'; END IF;
 IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
   WHERE r.rolname IN ('tenant_alpha','tenant_beta','replay_service')) THEN RAISE EXCEPTION 'role membership'; END IF;
END $$;
SELECT 'rls_checks_passed';
