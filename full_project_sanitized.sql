--
-- PostgreSQL database dump
--

-- Dumped from database version 17.4
-- Dumped by pg_dump version 17.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET [redacted-token] = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET [redacted-token] = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA auth;


--
-- Name: extensions; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA extensions;


--
-- Name: graphql; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql;


--
-- Name: graphql_public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA graphql_public;


--
-- Name: pgbouncer; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA pgbouncer;


--
-- Name: realtime; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA realtime;


--
-- Name: storage; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA storage;


--
-- Name: supabase_migrations; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA supabase_migrations;


--
-- Name: vault; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA vault;


--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- Name: EXTENSION citext; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION citext IS 'data type for case-insensitive character strings';


--
-- Name: pg_graphql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_graphql WITH SCHEMA graphql;


--
-- Name: EXTENSION pg_graphql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_graphql IS 'pg_graphql: GraphQL support';


--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA extensions;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: supabase_vault; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS supabase_vault WITH SCHEMA vault;


--
-- Name: EXTENSION supabase_vault; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION supabase_vault IS 'Supabase Vault Extension';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: aal_level; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.aal_level AS ENUM (
    'aal1',
    'aal2',
    'aal3'
);


--
-- Name: code_challenge_method; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.code_challenge_method AS ENUM (
    's256',
    'plain'
);


--
-- Name: factor_status; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_status AS ENUM (
    'unverified',
    'verified'
);


--
-- Name: factor_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.factor_type AS ENUM (
    'totp',
    'webauthn',
    'phone'
);


--
-- Name: oauth_registration_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.oauth_registration_type AS ENUM (
    'dynamic',
    'manual'
);


--
-- Name: one_time_token_type; Type: TYPE; Schema: auth; Owner: -
--

CREATE TYPE auth.one_time_token_type AS ENUM (
    'confirmation_token',
    'reauthentication_token',
    'recovery_token',
    'email_change_token_new',
    '[redacted-token]',
    'phone_change_token'
);


--
-- Name: action; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.action AS ENUM (
    'INSERT',
    'UPDATE',
    'DELETE',
    'TRUNCATE',
    'ERROR'
);


--
-- Name: equality_op; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.equality_op AS ENUM (
    'eq',
    'neq',
    'lt',
    'lte',
    'gt',
    'gte',
    'in'
);


--
-- Name: user_defined_filter; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.user_defined_filter AS (
	column_name text,
	op realtime.equality_op,
	value text
);


--
-- Name: wal_column; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.wal_column AS (
	name text,
	type_name text,
	type_oid oid,
	value jsonb,
	is_pkey boolean,
	is_selectable boolean
);


--
-- Name: wal_rls; Type: TYPE; Schema: realtime; Owner: -
--

CREATE TYPE realtime.wal_rls AS (
	wal jsonb,
	is_rls_enabled boolean,
	subscription_ids uuid[],
	errors text[]
);


--
-- Name: email(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.email() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;


--
-- Name: FUNCTION email(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.email() IS 'Deprecated. Use auth.jwt() -> ''email'' instead.';


--
-- Name: jwt(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.jwt() RETURNS jsonb
    LANGUAGE sql STABLE
    AS $$
  select 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;


--
-- Name: role(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.role() RETURNS text
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;


--
-- Name: FUNCTION role(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.role() IS 'Deprecated. Use auth.jwt() -> ''role'' instead.';


--
-- Name: uid(); Type: FUNCTION; Schema: auth; Owner: -
--

CREATE FUNCTION auth.uid() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$
  select 
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;


--
-- Name: FUNCTION uid(); Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON FUNCTION auth.uid() IS 'Deprecated. Use auth.jwt() -> ''sub'' instead.';


--
-- Name: grant_pg_cron_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_cron_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT
    FROM [redacted-token]() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_cron'
  )
  THEN
    grant usage on schema cron to postgres with grant option;

    alter default privileges in schema cron grant all on tables to postgres with grant option;
    alter default privileges in schema cron grant all on functions to postgres with grant option;
    alter default privileges in schema cron grant all on sequences to postgres with grant option;

    alter default privileges for user supabase_admin in schema cron grant all
        on sequences to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on tables to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on functions to postgres with grant option;

    grant all privileges on all tables in schema cron to postgres with grant option;
    revoke all on table cron.job from postgres;
    grant select on table cron.job to postgres with grant option;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_cron_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_cron_access() IS 'Grants access to pg_cron';


--
-- Name: grant_pg_graphql_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_graphql_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    func_is_graphql_resolve bool;
BEGIN
    func_is_graphql_resolve = (
        SELECT n.proname = 'resolve'
        FROM [redacted-token]() AS ev
        LEFT JOIN pg_catalog.pg_proc AS n
        ON ev.objid = n.oid
    );

    IF func_is_graphql_resolve
    THEN
        -- Update public wrapper to pass all arguments through to the pg_graphql resolve func
        DROP FUNCTION IF EXISTS graphql_public.graphql;
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language sql
        as $$
            select graphql.resolve(
                query := query,
                variables := coalesce(variables, '{}'),
                "operationName" := "operationName",
                extensions := extensions
            );
        $$;

        -- This hook executes when `graphql.resolve` is created. That is not necessarily the last
        -- function in the extension so we need to grant permissions on existing entities AND
        -- update default permissions to any others that are created after `graphql.resolve`
        grant usage on schema graphql to postgres, anon, authenticated, service_role;
        grant select on all tables in schema graphql to postgres, anon, authenticated, service_role;
        grant execute on all functions in schema graphql to postgres, anon, authenticated, service_role;
        grant all on all sequences in schema graphql to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on tables to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on functions to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on sequences to postgres, anon, authenticated, service_role;

        -- Allow postgres role to allow granting usage on graphql and graphql_public schemas to custom roles
        grant usage on schema graphql_public to postgres with grant option;
        grant usage on schema graphql to postgres with grant option;
    END IF;

END;
$_$;


--
-- Name: FUNCTION grant_pg_graphql_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_graphql_access() IS 'Grants access to pg_graphql';


--
-- Name: grant_pg_net_access(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.grant_pg_net_access() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM [redacted-token]() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_net'
  )
  THEN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = '[redacted-token]'
    )
    THEN
      CREATE USER [redacted-token] NOINHERIT CREATEROLE LOGIN NOREPLICATION;
    END IF;

    GRANT USAGE ON SCHEMA net TO [redacted-token], postgres, anon, authenticated, service_role;

    IF EXISTS (
      SELECT FROM pg_extension
      WHERE extname = 'pg_net'
      -- all versions in use on existing projects as of 2025-02-20
      -- version 0.12.0 onwards don't need these applied
      AND extversion IN ('0.2', '0.6', '0.7', '0.7.1', '0.8', '0.10.0', '0.11.0')
    ) THEN
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;

      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;

      REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;

      GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO [redacted-token], postgres, anon, authenticated, service_role;
      GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO [redacted-token], postgres, anon, authenticated, service_role;
    END IF;
  END IF;
END;
$$;


--
-- Name: FUNCTION grant_pg_net_access(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.grant_pg_net_access() IS 'Grants access to pg_net';


--
-- Name: pgrst_ddl_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_ddl_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN SELECT * FROM [redacted-token]()
  LOOP
    IF cmd.command_tag IN (
      'CREATE SCHEMA', 'ALTER SCHEMA'
    , 'CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE'
    , 'CREATE FOREIGN TABLE', 'ALTER FOREIGN TABLE'
    , 'CREATE VIEW', 'ALTER VIEW'
    , 'CREATE MATERIALIZED VIEW', 'ALTER MATERIALIZED VIEW'
    , 'CREATE FUNCTION', 'ALTER FUNCTION'
    , 'CREATE TRIGGER'
    , 'CREATE TYPE', 'ALTER TYPE'
    , 'CREATE RULE'
    , 'COMMENT'
    )
    -- don't notify in case of CREATE TEMP table or other objects created on pg_temp
    AND cmd.schema_name is distinct from 'pg_temp'
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: pgrst_drop_watch(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.pgrst_drop_watch() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN SELECT * FROM [redacted-token]()
  LOOP
    IF obj.object_type IN (
      'schema'
    , 'table'
    , 'foreign table'
    , 'view'
    , 'materialized view'
    , 'function'
    , 'trigger'
    , 'type'
    , 'rule'
    )
    AND obj.is_temporary IS false -- no pg_temp objects
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END; $$;


--
-- Name: set_graphql_placeholder(); Type: FUNCTION; Schema: extensions; Owner: -
--

CREATE FUNCTION extensions.set_graphql_placeholder() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $_$
    DECLARE
    graphql_is_dropped bool;
    BEGIN
    graphql_is_dropped = (
        SELECT ev.schema_name = 'graphql_public'
        FROM [redacted-token]() AS ev
        WHERE ev.schema_name = 'graphql_public'
    );

    IF graphql_is_dropped
    THEN
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language plpgsql
        as $$
            DECLARE
                server_version float;
            BEGIN
                server_version = (SELECT (SPLIT_PART((select version()), ' ', 2))::float);

                IF server_version >= 14 THEN
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql extension is not enabled.'
                            )
                        )
                    );
                ELSE
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql is only available on projects running Postgres 14 onwards.'
                            )
                        )
                    );
                END IF;
            END;
        $$;
    END IF;

    END;
$_$;


--
-- Name: FUNCTION set_graphql_placeholder(); Type: COMMENT; Schema: extensions; Owner: -
--

COMMENT ON FUNCTION extensions.set_graphql_placeholder() IS 'Reintroduces placeholder function for graphql_public.graphql';


--
-- Name: get_auth(text); Type: FUNCTION; Schema: pgbouncer; Owner: -
--

CREATE FUNCTION pgbouncer.get_auth(p_usename text) RETURNS TABLE(username text, password text)
    LANGUAGE plpgsql SECURITY DEFINER
    AS $_$
begin
    raise debug 'PgBouncer auth request: %', p_usename;

    return query
    select 
        rolname::text, 
        case when rolvaliduntil < now() 
            then null 
            else rolpassword::text 
        end 
    from pg_authid 
    where rolname=$1 and rolcanlogin;
end;
$_$;


--
-- Name: [redacted-token](); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.[redacted-token]() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  -- org_id'yi request'ten çek
  select r.org_id into new.org_id
  from customer_requests r
  where r.id = new.request_id;

  -- stilist ad/e-postayı denormalize et
  select s.name, s.email into new.stylist_name, new.stylist_email
  from stylists s
  where s.id = new.stylist_id;

  return new;
end $$;


--
-- Name: [redacted-token](); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.[redacted-token]() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  update request_stylists
  set stylist_name  = new.name,
      stylist_email = new.email
  where stylist_id = new.id;
  return null;
end $$;


--
-- Name: [redacted-token](); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.[redacted-token]() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.sequence_number = COALESCE(
        (SELECT MAX(sequence_number) + 1 
         FROM email_logs 
         WHERE customer_id = NEW.customer_id),
        1
    );
    RETURN NEW;
END;
$$;


--
-- Name: [redacted-token](); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.[redacted-token]() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


--
-- Name: apply_rls(jsonb, integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer DEFAULT (1024 * 1024)) RETURNS SETOF realtime.wal_rls
    LANGUAGE plpgsql
    AS $$
declare
-- Regclass of the table e.g. public.notes
entity_ regclass = (quote_ident(wal ->> 'schema') || '.' || quote_ident(wal ->> 'table'))::regclass;

-- I, U, D, T: insert, update ...
action realtime.action = (
    case wal ->> 'action'
        when 'I' then 'INSERT'
        when 'U' then 'UPDATE'
        when 'D' then 'DELETE'
        else 'ERROR'
    end
);

-- Is row level security enabled for the table
is_rls_enabled bool = relrowsecurity from pg_class where oid = entity_;

subscriptions realtime.subscription[] = array_agg(subs)
    from
        realtime.subscription subs
    where
        subs.entity = entity_;

-- Subscription vars
roles regrole[] = array_agg(distinct us.claims_role::text)
    from
        unnest(subscriptions) us;

working_role regrole;
claimed_role regrole;
claims jsonb;

subscription_id uuid;
subscription_has_access bool;
[redacted-token] uuid[] = '{}';

-- structured info for wal's columns
columns realtime.wal_column[];
-- previous identity values for update/delete
old_columns realtime.wal_column[];

[redacted-token] boolean = octet_length(wal::text) > max_record_bytes;

-- Primary jsonb output for record
output jsonb;

begin
perform set_config('role', null, true);

columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'columns') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

old_columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'identity') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

for working_role in select * from unnest(roles) loop

    -- Update `is_selectable` for columns and old_columns
    columns =
        array_agg(
            (
                c.name,
                c.type_name,
                c.type_oid,
                c.value,
                c.is_pkey,
                pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
            )::realtime.wal_column
        )
        from
            unnest(columns) c;

    old_columns =
            array_agg(
                (
                    c.name,
                    c.type_name,
                    c.type_oid,
                    c.value,
                    c.is_pkey,
                    pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
                )::realtime.wal_column
            )
            from
                unnest(old_columns) c;

    if action <> 'DELETE' and count(1) = 0 from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            -- subscriptions is already filtered by entity
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 400: Bad Request, no primary key']
        )::realtime.wal_rls;

    -- The claims role does not have SELECT permission to the primary key of entity
    elsif action <> 'DELETE' and sum(c.is_selectable::int) <> count(1) from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 401: Unauthorized']
        )::realtime.wal_rls;

    else
        output = jsonb_build_object(
            'schema', wal ->> 'schema',
            'table', wal ->> 'table',
            'type', action,
            'commit_timestamp', to_char(
                ((wal ->> 'timestamp')::timestamptz at time zone 'utc'),
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ),
            'columns', (
                select
                    jsonb_agg(
                        jsonb_build_object(
                            'name', pa.attname,
                            'type', pt.typname
                        )
                        order by pa.attnum asc
                    )
                from
                    pg_attribute pa
                    join pg_type pt
                        on pa.atttypid = pt.oid
                where
                    attrelid = entity_
                    and attnum > 0
                    and pg_catalog.has_column_privilege(working_role, entity_, pa.attname, 'SELECT')
            )
        )
        -- Add "record" key for insert and update
        || case
            when action in ('INSERT', 'UPDATE') then
                jsonb_build_object(
                    'record',
                    (
                        select
                            jsonb_object_agg(
                                -- if unchanged toast, get column name and value from old record
                                coalesce((c).name, (oc).name),
                                case
                                    when (c).name is null then (oc).value
                                    else (c).value
                                end
                            )
                        from
                            unnest(columns) c
                            full outer join unnest(old_columns) oc
                                on (c).name = (oc).name
                        where
                            coalesce((c).is_selectable, (oc).is_selectable)
                            and ( not [redacted-token] or (octet_length((c).value::text) <= 64))
                    )
                )
            else '{}'::jsonb
        end
        -- Add "old_record" key for update and delete
        || case
            when action = 'UPDATE' then
                jsonb_build_object(
                        'old_record',
                        (
                            select jsonb_object_agg((c).name, (c).value)
                            from unnest(old_columns) c
                            where
                                (c).is_selectable
                                and ( not [redacted-token] or (octet_length((c).value::text) <= 64))
                        )
                    )
            when action = 'DELETE' then
                jsonb_build_object(
                    'old_record',
                    (
                        select jsonb_object_agg((c).name, (c).value)
                        from unnest(old_columns) c
                        where
                            (c).is_selectable
                            and ( not [redacted-token] or (octet_length((c).value::text) <= 64))
                            and ( not is_rls_enabled or (c).is_pkey ) -- if RLS enabled, we can't secure deletes so filter to pkey
                    )
                )
            else '{}'::jsonb
        end;

        -- Create the prepared statement
        if is_rls_enabled and action <> 'DELETE' then
            if (select 1 from pg_prepared_statements where name = 'walrus_rls_stmt' limit 1) > 0 then
                deallocate walrus_rls_stmt;
            end if;
            execute realtime.[redacted-token]('walrus_rls_stmt', entity_, columns);
        end if;

        [redacted-token] = '{}';

        for subscription_id, claims in (
                select
                    subs.subscription_id,
                    subs.claims
                from
                    unnest(subscriptions) subs
                where
                    subs.entity = entity_
                    and subs.claims_role = working_role
                    and (
                        realtime.[redacted-token](columns, subs.filters)
                        or (
                          action = 'DELETE'
                          and realtime.[redacted-token](old_columns, subs.filters)
                        )
                    )
        ) loop

            if not is_rls_enabled or action = 'DELETE' then
                [redacted-token] = [redacted-token] || subscription_id;
            else
                -- Check if RLS allows the role to see the record
                perform
                    -- Trim leading and trailing quotes from working_role because set_config
                    -- doesn't recognize the role as valid if they are included
                    set_config('role', trim(both '"' from working_role::text), true),
                    set_config('request.jwt.claims', claims::text, true);

                execute 'execute walrus_rls_stmt' into subscription_has_access;

                if subscription_has_access then
                    [redacted-token] = [redacted-token] || subscription_id;
                end if;
            end if;
        end loop;

        perform set_config('role', null, true);

        return next (
            output,
            is_rls_enabled,
            [redacted-token],
            case
                when [redacted-token] then array['Error 413: Payload Too Large']
                else '{}'
            end
        )::realtime.wal_rls;

    end if;
end loop;

perform set_config('role', null, true);
end;
$$;


--
-- Name: broadcast_changes(text, text, text, text, text, record, record, text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text DEFAULT 'ROW'::text) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    -- Declare a variable to hold the JSONB representation of the row
    row_data jsonb := '{}'::jsonb;
BEGIN
    IF level = 'STATEMENT' THEN
        RAISE EXCEPTION 'function can only be triggered for each row, not for each statement';
    END IF;
    -- Check the operation type and handle accordingly
    IF operation = 'INSERT' OR operation = 'UPDATE' OR operation = 'DELETE' THEN
        row_data := jsonb_build_object('old_record', OLD, 'record', NEW, 'operation', operation, 'table', table_name, 'schema', table_schema);
        PERFORM realtime.send (row_data, event_name, topic_name);
    ELSE
        RAISE EXCEPTION 'Unexpected operation type: %', operation;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Failed to process the row: %', SQLERRM;
END;

$$;


--
-- Name: [redacted-token](text, regclass, realtime.wal_column[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.[redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]) RETURNS text
    LANGUAGE sql
    AS $$
      /*
      Builds a sql string that, if executed, creates a prepared statement to
      tests retrive a row from *entity* by its primary key columns.
      Example
          select realtime.[redacted-token]('public.notes', '{"id"}'::text[], '{"bigint"}'::text[])
      */
          select
      'prepare ' || prepared_statement_name || ' as
          select
              exists(
                  select
                      1
                  from
                      ' || entity || '
                  where
                      ' || string_agg(quote_ident(pkc.name) || '=' || quote_nullable(pkc.value #>> '{}') , ' and ') || '
              )'
          from
              unnest(columns) pkc
          where
              pkc.is_pkey
          group by
              entity
      $$;


--
-- Name: cast(text, regtype); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime."cast"(val text, type_ regtype) RETURNS jsonb
    LANGUAGE plpgsql IMMUTABLE
    AS $$
    declare
      res jsonb;
    begin
      execute format('select to_jsonb(%L::'|| type_::text || ')', val)  into res;
      return res;
    end
    $$;


--
-- Name: check_equality_op(realtime.equality_op, regtype, text, text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
      /*
      Casts *val_1* and *val_2* as type *type_* and check the *op* condition for truthiness
      */
      declare
          op_symbol text = (
              case
                  when op = 'eq' then '='
                  when op = 'neq' then '!='
                  when op = 'lt' then '<'
                  when op = 'lte' then '<='
                  when op = 'gt' then '>'
                  when op = 'gte' then '>='
                  when op = 'in' then '= any'
                  else 'UNKNOWN OP'
              end
          );
          res boolean;
      begin
          execute format(
              'select %L::'|| type_::text || ' ' || op_symbol
              || ' ( %L::'
              || (
                  case
                      when op = 'in' then type_::text || '[]'
                      else type_::text end
              )
              || ')', val_1, val_2) into res;
          return res;
      end;
      $$;


--
-- Name: [redacted-token](realtime.wal_column[], realtime.user_defined_filter[]); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.[redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $_$
    /*
    Should the record be visible (true) or filtered out (false) after *filters* are applied
    */
        select
            -- Default to allowed when no filters present
            $2 is null -- no filters. this should not happen because subscriptions has a default
            or array_length($2, 1) is null -- array length of an empty array is null
            or bool_and(
                coalesce(
                    realtime.check_equality_op(
                        op:=f.op,
                        type_:=coalesce(
                            col.type_oid::regtype, -- null when wal2json version <= 2.4
                            col.type_name::regtype
                        ),
                        -- cast jsonb to text
                        val_1:=col.value #>> '{}',
                        val_2:=f.value
                    ),
                    false -- if null, filter does not match
                )
            )
        from
            unnest(filters) f
            join unnest(columns) col
                on f.column_name = col.name;
    $_$;


--
-- Name: list_changes(name, name, integer, integer); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) RETURNS SETOF realtime.wal_rls
    LANGUAGE sql
    SET log_min_messages TO 'fatal'
    AS $$
      with pub as (
        select
          concat_ws(
            ',',
            case when bool_or(pubinsert) then 'insert' else null end,
            case when bool_or(pubupdate) then 'update' else null end,
            case when bool_or(pubdelete) then 'delete' else null end
          ) as w2j_actions,
          coalesce(
            string_agg(
              realtime.quote_wal2json(format('%I.%I', schemaname, tablename)::regclass),
              ','
            ) filter (where ppt.tablename is not null and ppt.tablename not like '% %'),
            ''
          ) w2j_add_tables
        from
          pg_publication pp
          left join pg_publication_tables ppt
            on pp.pubname = ppt.pubname
        where
          pp.pubname = publication
        group by
          pp.pubname
        limit 1
      ),
      w2j as (
        select
          x.*, pub.w2j_add_tables
        from
          pub,
          [redacted-token](
            slot_name, null, max_changes,
            'include-pk', 'true',
            'include-transaction', 'false',
            'include-timestamp', 'true',
            'include-type-oids', 'true',
            'format-version', '2',
            'actions', pub.w2j_actions,
            'add-tables', pub.w2j_add_tables
          ) x
      )
      select
        xyz.wal,
        xyz.is_rls_enabled,
        xyz.subscription_ids,
        xyz.errors
      from
        w2j,
        realtime.apply_rls(
          wal := w2j.data::jsonb,
          max_record_bytes := max_record_bytes
        ) xyz(wal, is_rls_enabled, subscription_ids, errors)
      where
        w2j.w2j_add_tables <> ''
        and xyz.subscription_ids[1] is not null
    $$;


--
-- Name: quote_wal2json(regclass); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.quote_wal2json(entity regclass) RETURNS text
    LANGUAGE sql IMMUTABLE STRICT
    AS $$
      select
        (
          select string_agg('' || ch,'')
          from unnest(string_to_array(nsp.nspname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
        )
        || '.'
        || (
          select string_agg('' || ch,'')
          from unnest(string_to_array(pc.relname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
          )
      from
        pg_class pc
        join pg_namespace nsp
          on pc.relnamespace = nsp.oid
      where
        pc.oid = entity
    $$;


--
-- Name: send(jsonb, text, text, boolean); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.send(payload jsonb, event text, topic text, private boolean DEFAULT true) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  BEGIN
    -- Set the topic configuration
    EXECUTE format('SET LOCAL realtime.topic TO %L', topic);

    -- Attempt to insert the message
    INSERT INTO realtime.messages (payload, event, topic, private, extension)
    VALUES (payload, event, topic, private, 'broadcast');
  EXCEPTION
    WHEN OTHERS THEN
      -- Capture and notify the error
      RAISE WARNING '[redacted-token]: %', SQLERRM;
  END;
END;
$$;


--
-- Name: [redacted-token](); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.[redacted-token]() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    /*
    Validates that the user defined filters for a subscription:
    - refer to valid columns that the claimed role may access
    - values are coercable to the correct column type
    */
    declare
        col_names text[] = coalesce(
                array_agg(c.column_name order by c.ordinal_position),
                '{}'::text[]
            )
            from
                information_schema.columns c
            where
                format('%I.%I', c.table_schema, c.table_name)::regclass = new.entity
                and pg_catalog.has_column_privilege(
                    (new.claims ->> 'role'),
                    format('%I.%I', c.table_schema, c.table_name)::regclass,
                    c.column_name,
                    'SELECT'
                );
        filter realtime.user_defined_filter;
        col_type regtype;

        in_val jsonb;
    begin
        for filter in select * from unnest(new.filters) loop
            -- Filtered column is valid
            if not filter.column_name = any(col_names) then
                raise exception 'invalid column for filter %', filter.column_name;
            end if;

            -- Type is sanitized and safe for string interpolation
            col_type = (
                select atttypid::regtype
                from pg_catalog.pg_attribute
                where attrelid = new.entity
                      and attname = filter.column_name
            );
            if col_type is null then
                raise exception 'failed to lookup type for column %', filter.column_name;
            end if;

            -- Set maximum number of entries for in filter
            if filter.op = 'in'::realtime.equality_op then
                in_val = realtime.cast(filter.value, (col_type::text || '[]')::regtype);
                if coalesce(jsonb_array_length(in_val), 0) > 100 then
                    raise exception 'too many values for `in` filter. Maximum 100';
                end if;
            else
                -- raises an exception if value is not coercable to type
                perform realtime.cast(filter.value, col_type);
            end if;

        end loop;

        -- Apply consistent order to filters so the unique constraint on
        -- (subscription_id, entity, filters) can't be tricked by a different filter order
        new.filters = coalesce(
            array_agg(f order by f.column_name, f.op, f.value),
            '{}'
        ) from unnest(new.filters) f;

        return new;
    end;
    $$;


--
-- Name: to_regrole(text); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.to_regrole(role_name text) RETURNS regrole
    LANGUAGE sql IMMUTABLE
    AS $$ select role_name::regrole $$;


--
-- Name: topic(); Type: FUNCTION; Schema: realtime; Owner: -
--

CREATE FUNCTION realtime.topic() RETURNS text
    LANGUAGE sql STABLE
    AS $$
select nullif(current_setting('realtime.topic', true), '')::text;
$$;


--
-- Name: can_insert_object(text, text, uuid, jsonb); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.can_insert_object(bucketid text, name text, owner uuid, metadata jsonb) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO "storage"."objects" ("bucket_id", "name", "owner", "metadata") VALUES (bucketid, name, owner, metadata);
  -- hack to rollback the successful insert
  RAISE sqlstate 'PT200' using
  message = 'ROLLBACK',
  detail = 'rollback successful insert';
END
$$;


--
-- Name: extension(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.extension(name text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
_filename text;
BEGIN
	select string_to_array(name, '/') into _parts;
	select _parts[array_length(_parts,1)] into _filename;
	-- @redacted-handle return the last part instead of 2
	return reverse(split_part(reverse(_filename), '.', 1));
END
$$;


--
-- Name: filename(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.filename(name text) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[array_length(_parts,1)];
END
$$;


--
-- Name: foldername(text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.foldername(name text) RETURNS text[]
    LANGUAGE plpgsql
    AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[1:array_length(_parts,1)-1];
END
$$;


--
-- Name: get_size_by_bucket(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.get_size_by_bucket() RETURNS TABLE(size bigint, bucket_id text)
    LANGUAGE plpgsql
    AS $$
BEGIN
    return query
        select sum((metadata->>'size')::int) as size, obj.bucket_id
        from "storage".objects as obj
        group by obj.bucket_id;
END
$$;


--
-- Name: [redacted-token](text, text, text, integer, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.[redacted-token](bucket_id text, prefix_param text, delimiter_param text, max_keys integer DEFAULT 100, next_key_token text DEFAULT ''::text, next_upload_token text DEFAULT ''::text) RETURNS TABLE(key text, id text, created_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $_$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(key COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                        substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1)))
                    ELSE
                        key
                END AS key, id, created_at
            FROM
                storage.s3_multipart_uploads
            WHERE
                bucket_id = $5 AND
                key ILIKE $1 || ''%'' AND
                CASE
                    WHEN $4 != '''' AND $6 = '''' THEN
                        CASE
                            WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                                substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                key COLLATE "C" > $4
                            END
                    ELSE
                        true
                END AND
                CASE
                    WHEN $6 != '''' THEN
                        id COLLATE "C" > $6
                    ELSE
                        true
                    END
            ORDER BY
                key COLLATE "C" ASC, created_at ASC) as e order by key COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_key_token, bucket_id, next_upload_token;
END;
$_$;


--
-- Name: [redacted-token](text, text, text, integer, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.[redacted-token](bucket_id text, prefix_param text, delimiter_param text, max_keys integer DEFAULT 100, start_after text DEFAULT ''::text, next_token text DEFAULT ''::text) RETURNS TABLE(name text, id uuid, metadata jsonb, updated_at timestamp with time zone)
    LANGUAGE plpgsql
    AS $_$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(name COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(name from length($1) + 1)) > 0 THEN
                        substring(name from 1 for length($1) + position($2 IN substring(name from length($1) + 1)))
                    ELSE
                        name
                END AS name, id, metadata, updated_at
            FROM
                storage.objects
            WHERE
                bucket_id = $5 AND
                name ILIKE $1 || ''%'' AND
                CASE
                    WHEN $6 != '''' THEN
                    name COLLATE "C" > $6
                ELSE true END
                AND CASE
                    WHEN $4 != '''' THEN
                        CASE
                            WHEN position($2 IN substring(name from length($1) + 1)) > 0 THEN
                                substring(name from 1 for length($1) + position($2 IN substring(name from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                name COLLATE "C" > $4
                            END
                    ELSE
                        true
                END
            ORDER BY
                name COLLATE "C" ASC) as e order by name COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_token, bucket_id, start_after;
END;
$_$;


--
-- Name: operation(); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.operation() RETURNS text
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    RETURN current_setting('storage.operation', true);
END;
$$;


--
-- Name: search(text, text, integer, integer, integer, text, text, text); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.search(prefix text, bucketname text, limits integer DEFAULT 100, levels integer DEFAULT 1, offsets integer DEFAULT 0, search text DEFAULT ''::text, sortcolumn text DEFAULT 'name'::text, sortorder text DEFAULT 'asc'::text) RETURNS TABLE(name text, id uuid, updated_at timestamp with time zone, created_at timestamp with time zone, last_accessed_at timestamp with time zone, metadata jsonb)
    LANGUAGE plpgsql STABLE
    AS $_$
declare
  v_order_by text;
  v_sort_order text;
begin
  case
    when sortcolumn = 'name' then
      v_order_by = 'name';
    when sortcolumn = 'updated_at' then
      v_order_by = 'updated_at';
    when sortcolumn = 'created_at' then
      v_order_by = 'created_at';
    when sortcolumn = 'last_accessed_at' then
      v_order_by = 'last_accessed_at';
    else
      v_order_by = 'name';
  end case;

  case
    when sortorder = 'asc' then
      v_sort_order = 'asc';
    when sortorder = 'desc' then
      v_sort_order = 'desc';
    else
      v_sort_order = 'asc';
  end case;

  v_order_by = v_order_by || ' ' || v_sort_order;

  return query execute
    'with folders as (
       select path_tokens[$1] as folder
       from storage.objects
         where objects.name ilike $2 || $3 || ''%''
           and bucket_id = $4
           and array_length(objects.path_tokens, 1) <> $1
       group by folder
       order by folder ' || v_sort_order || '
     )
     (select folder as "name",
            null as id,
            null as updated_at,
            null as created_at,
            null as last_accessed_at,
            null as metadata from folders)
     union all
     (select path_tokens[$1] as "name",
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
     from storage.objects
     where objects.name ilike $2 || $3 || ''%''
       and bucket_id = $4
       and array_length(objects.path_tokens, 1) = $1
     order by ' || v_order_by || ')
     limit $5
     offset $6' using levels, prefix, search, bucketname, limits, offsets;
end;
$_$;


--
-- Name: [redacted-token](); Type: FUNCTION; Schema: storage; Owner: -
--

CREATE FUNCTION storage.[redacted-token]() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW; 
END;
$$;


SET default_tablespace = '';

SET [redacted-token] = heap;

--
-- Name: audit_log_entries; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.audit_log_entries (
    instance_id uuid,
    id uuid NOT NULL,
    payload json,
    created_at timestamp with time zone,
    ip_address character varying(64) DEFAULT ''::character varying NOT NULL
);


--
-- Name: TABLE audit_log_entries; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.audit_log_entries IS 'Auth: Audit trail for user actions.';


--
-- Name: flow_state; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.flow_state (
    id uuid NOT NULL,
    user_id uuid,
    auth_code text NOT NULL,
    code_challenge_method auth.code_challenge_method NOT NULL,
    code_challenge text NOT NULL,
    provider_type text NOT NULL,
    provider_access_token text,
    provider_refresh_token text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    authentication_method text NOT NULL,
    auth_code_issued_at timestamp with time zone
);


--
-- Name: TABLE flow_state; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.flow_state IS 'stores metadata for pkce logins';


--
-- Name: identities; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.identities (
    provider_id text NOT NULL,
    user_id uuid NOT NULL,
    identity_data jsonb NOT NULL,
    provider text NOT NULL,
    last_sign_in_at timestamp with time zone,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    email text GENERATED ALWAYS AS (lower((identity_data ->> 'email'::text))) STORED,
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


--
-- Name: TABLE identities; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.identities IS 'Auth: Stores identities associated to a user.';


--
-- Name: COLUMN identities.email; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.identities.email IS 'Auth: Email is a generated column that references the optional email property in the identity_data';


--
-- Name: instances; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.instances (
    id uuid NOT NULL,
    uuid uuid,
    raw_base_config text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);


--
-- Name: TABLE instances; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.instances IS 'Auth: Manages users across multiple sites.';


--
-- Name: mfa_amr_claims; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_amr_claims (
    session_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    authentication_method text NOT NULL,
    id uuid NOT NULL
);


--
-- Name: TABLE mfa_amr_claims; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_amr_claims IS 'auth: stores authenticator method reference claims for multi factor authentication';


--
-- Name: mfa_challenges; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_challenges (
    id uuid NOT NULL,
    factor_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    ip_address inet NOT NULL,
    otp_code text,
    web_authn_session_data jsonb
);


--
-- Name: TABLE mfa_challenges; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_challenges IS 'auth: stores metadata about challenge requests made';


--
-- Name: mfa_factors; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.mfa_factors (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    friendly_name text,
    factor_type auth.factor_type NOT NULL,
    status auth.factor_status NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    secret text,
    phone text,
    last_challenged_at timestamp with time zone,
    web_authn_credential jsonb,
    web_authn_aaguid uuid
);


--
-- Name: TABLE mfa_factors; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.mfa_factors IS 'auth: stores metadata about factors';


--
-- Name: oauth_clients; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.oauth_clients (
    id uuid NOT NULL,
    client_id text NOT NULL,
    client_secret_hash text NOT NULL,
    registration_type auth.oauth_registration_type NOT NULL,
    redirect_uris text NOT NULL,
    grant_types text NOT NULL,
    client_name text,
    client_uri text,
    logo_uri text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT [redacted-token] CHECK ((char_length(client_name) <= 1024)),
    CONSTRAINT [redacted-token] CHECK ((char_length(client_uri) <= 2048)),
    CONSTRAINT [redacted-token] CHECK ((char_length(logo_uri) <= 2048))
);


--
-- Name: one_time_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.one_time_tokens (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_type auth.one_time_token_type NOT NULL,
    token_hash text NOT NULL,
    relates_to text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT [redacted-token] CHECK ((char_length(token_hash) > 0))
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.refresh_tokens (
    instance_id uuid,
    id bigint NOT NULL,
    token character varying(255),
    user_id character varying(255),
    revoked boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    parent character varying(255),
    session_id uuid
);


--
-- Name: TABLE refresh_tokens; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.refresh_tokens IS 'Auth: Store of tokens used to refresh JWT tokens once they expire.';


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: auth; Owner: -
--

CREATE SEQUENCE auth.refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: auth; Owner: -
--

ALTER SEQUENCE auth.refresh_tokens_id_seq OWNED BY auth.refresh_tokens.id;


--
-- Name: saml_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_providers (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    entity_id text NOT NULL,
    metadata_xml text NOT NULL,
    metadata_url text,
    attribute_mapping jsonb,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    name_id_format text,
    CONSTRAINT "entity_id not empty" CHECK ((char_length(entity_id) > 0)),
    CONSTRAINT "metadata_url not empty" CHECK (((metadata_url = NULL::text) OR (char_length(metadata_url) > 0))),
    CONSTRAINT "metadata_xml not empty" CHECK ((char_length(metadata_xml) > 0))
);


--
-- Name: TABLE saml_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_providers IS 'Auth: Manages SAML Identity Provider connections.';


--
-- Name: saml_relay_states; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.saml_relay_states (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    request_id text NOT NULL,
    for_email text,
    redirect_to text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    flow_state_id uuid,
    CONSTRAINT "request_id not empty" CHECK ((char_length(request_id) > 0))
);


--
-- Name: TABLE saml_relay_states; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.saml_relay_states IS 'Auth: Contains SAML Relay State information for each Service Provider initiated login.';


--
-- Name: schema_migrations; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.schema_migrations (
    version character varying(255) NOT NULL
);


--
-- Name: TABLE schema_migrations; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.schema_migrations IS 'Auth: Manages updates to the auth system.';


--
-- Name: sessions; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    factor_id uuid,
    aal auth.aal_level,
    not_after timestamp with time zone,
    refreshed_at timestamp without time zone,
    user_agent text,
    ip inet,
    tag text
);


--
-- Name: TABLE sessions; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sessions IS 'Auth: Stores session data associated to a user.';


--
-- Name: COLUMN sessions.not_after; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sessions.not_after IS 'Auth: Not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';


--
-- Name: sso_domains; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_domains (
    id uuid NOT NULL,
    sso_provider_id uuid NOT NULL,
    domain text NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    CONSTRAINT "domain not empty" CHECK ((char_length(domain) > 0))
);


--
-- Name: TABLE sso_domains; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_domains IS 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';


--
-- Name: sso_providers; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.sso_providers (
    id uuid NOT NULL,
    resource_id text,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    disabled boolean,
    CONSTRAINT "resource_id not empty" CHECK (((resource_id = NULL::text) OR (char_length(resource_id) > 0)))
);


--
-- Name: TABLE sso_providers; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.sso_providers IS 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';


--
-- Name: COLUMN sso_providers.resource_id; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.sso_providers.resource_id IS 'Auth: Uniquely identifies a SSO provider according to a user-chosen resource ID (case insensitive), useful in infrastructure as code.';


--
-- Name: users; Type: TABLE; Schema: auth; Owner: -
--

CREATE TABLE auth.users (
    instance_id uuid,
    id uuid NOT NULL,
    aud character varying(255),
    role character varying(255),
    email character varying(255),
    encrypted_password character varying(255),
    email_confirmed_at timestamp with time zone,
    invited_at timestamp with time zone,
    confirmation_token character varying(255),
    confirmation_sent_at timestamp with time zone,
    recovery_token character varying(255),
    recovery_sent_at timestamp with time zone,
    email_change_token_new character varying(255),
    email_change character varying(255),
    email_change_sent_at timestamp with time zone,
    last_sign_in_at timestamp with time zone,
    raw_app_meta_data jsonb,
    raw_user_meta_data jsonb,
    is_super_admin boolean,
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    phone text DEFAULT NULL::character varying,
    phone_confirmed_at timestamp with time zone,
    phone_change text DEFAULT ''::character varying,
    phone_change_token character varying(255) DEFAULT ''::character varying,
    phone_change_sent_at timestamp with time zone,
    confirmed_at timestamp with time zone GENERATED ALWAYS AS (LEAST(email_confirmed_at, phone_confirmed_at)) STORED,
    [redacted-token] character varying(255) DEFAULT ''::character varying,
    [redacted-token] smallint DEFAULT 0,
    banned_until timestamp with time zone,
    reauthentication_token character varying(255) DEFAULT ''::character varying,
    [redacted-token] timestamp with time zone,
    is_sso_user boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    is_anonymous boolean DEFAULT false NOT NULL,
    CONSTRAINT [redacted-token] CHECK ((([redacted-token] >= 0) AND ([redacted-token] <= 2)))
);


--
-- Name: TABLE users; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON TABLE auth.users IS 'Auth: Stores user login data within a secure schema.';


--
-- Name: COLUMN users.is_sso_user; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON COLUMN auth.users.is_sso_user IS 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';


--
-- Name: activity_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activity_logs (
    id integer NOT NULL,
    org_id text,
    customer_id text NOT NULL,
    action text NOT NULL,
    action_details text,
    performed_by text,
    "timestamp" timestamp with time zone DEFAULT now(),
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: activity_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.activity_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: activity_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.activity_logs_id_seq OWNED BY public.activity_logs.id;


--
-- Name: business_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.business_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id text NOT NULL,
    business_name text NOT NULL,
    business_email text NOT NULL,
    business_phone text,
    business_address text,
    gpt_system_prompt text,
    gpt_model text DEFAULT 'gpt-4'::text,
    email_signature text,
    auto_reply_enabled boolean DEFAULT true,
    google_calendar_id text,
    [redacted-token] integer DEFAULT 120,
    buffer_time integer DEFAULT 30,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    settings jsonb
);


--
-- Name: customer_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    customer_id text DEFAULT concat('CUST-', (EXTRACT(epoch FROM now()))::text, '-', "substring"((gen_random_uuid())::text, 1, 4)) NOT NULL,
    org_id text NOT NULL,
    customer_name text NOT NULL,
    customer_email public.citext NOT NULL,
    customer_phone text,
    event_date date NOT NULL,
    ready_by_time time without time zone NOT NULL,
    event_start_time time without time zone,
    service_location text NOT NULL,
    number_of_hair integer DEFAULT 0,
    number_of_makeup integer DEFAULT 0,
    customer_notes text,
    admin_notes text,
    how_did_you_hear text,
    current_status text DEFAULT 'New Submission'::text,
    ai_initial_draft text,
    ai_follow_up_draft text,
    customer_reply text,
    last_email_sent text,
    ai_event_summary text,
    base_price numeric(10,2),
    adjusted_price numeric(10,2),
    final_price numeric(10,2),
    deposit_amount numeric(10,2) DEFAULT 250.00,
    travel_fee numeric(10,2) DEFAULT 0.00,
    payment_status text DEFAULT 'pending'::text,
    payment_method text,
    stripe_invoice_id text,
    payment_link text,
    amount_paid numeric(10,2) DEFAULT 0.00,
    total_people integer GENERATED ALWAYS AS ((number_of_hair + number_of_makeup)) STORED,
    service_type text GENERATED ALWAYS AS (
CASE
    WHEN ((number_of_hair > 0) AND (number_of_makeup > 0)) THEN 'both'::text
    WHEN (number_of_hair > 0) THEN 'hair'::text
    WHEN (number_of_makeup > 0) THEN 'makeup'::text
    ELSE 'none'::text
END) STORED,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    email_subject_current text,
    google_event_id text,
    reminder_sent boolean DEFAULT false,
    reminder_sent_at timestamp with time zone,
    last_email_sent_at timestamp with time zone,
    last_customer_reply_at timestamp with time zone,
    payment_received_at timestamp with time zone,
    tz text DEFAULT 'America/New_York'::text,
    summary_generated_at timestamp with time zone,
    ai_analysis jsonb,
    conversation_summary text,
    payment_date timestamp with time zone,
    match_confidence integer DEFAULT 100,
    balance_remaining numeric(10,2)
);


--
-- Name: email_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    customer_id text NOT NULL,
    org_id text NOT NULL,
    direction text NOT NULL,
    email_from text NOT NULL,
    email_to text NOT NULL,
    email_subject text,
    email_body text NOT NULL,
    sent_by text,
    sequence_number integer,
    thread_id text,
    "timestamp" timestamp with time zone DEFAULT now(),
    message_id text,
    in_reply_to text,
    headers jsonb,
    created_at timestamp with time zone DEFAULT now(),
    client_message_id text,
    delivery_status text,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT [redacted-token] CHECK ((direction = ANY (ARRAY['outbound'::text, 'inbound'::text]))),
    CONSTRAINT [redacted-token] CHECK ((delivery_status = ANY (ARRAY['queued'::text, 'sent'::text, 'failed'::text, 'skipped'::text])))
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    domain text,
    settings jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: payment_method_options; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_method_options (
    id integer NOT NULL,
    value text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0
);


--
-- Name: [redacted-token]; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.[redacted-token]
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: [redacted-token]; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.[redacted-token] OWNED BY public.payment_method_options.id;


--
-- Name: payment_status_options; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payment_status_options (
    id integer NOT NULL,
    value text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0
);


--
-- Name: [redacted-token]; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.[redacted-token]
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: [redacted-token]; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.[redacted-token] OWNED BY public.payment_status_options.id;


--
-- Name: pricing_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pricing_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id text DEFAULT 'le-glam-team'::text NOT NULL,
    service_type text NOT NULL,
    base_price numeric(8,2) NOT NULL,
    per_person_price numeric(8,2) NOT NULL,
    per_mile_rate numeric(4,2) DEFAULT 0.75,
    minimum_travel_fee numeric(8,2) DEFAULT 40.00,
    long_distance_fee numeric(8,2) DEFAULT 50.00,
    long_distance_threshold integer DEFAULT 100,
    weekend_multiplier numeric(3,2) DEFAULT 1.00,
    holiday_multiplier numeric(3,2) DEFAULT 1.00,
    deposit_required numeric(8,2) DEFAULT 250.00,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: request_stylists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.request_stylists (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    stylist_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id text NOT NULL,
    stylist_name text,
    stylist_email text
);


--
-- Name: status_options; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.status_options (
    id integer NOT NULL,
    value text NOT NULL,
    label text NOT NULL,
    sort_order integer DEFAULT 0
);


--
-- Name: status_options_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.status_options_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: status_options_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.status_options_id_seq OWNED BY public.status_options.id;


--
-- Name: stylist_availability; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stylist_availability (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    stylist_id uuid NOT NULL,
    available_date date NOT NULL,
    start_time time without time zone DEFAULT '08:00:00'::time without time zone,
    end_time time without time zone DEFAULT '18:00:00'::time without time zone,
    is_booked boolean DEFAULT false,
    customer_id text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: stylists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stylists (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    email public.citext,
    phone text,
    specialty text NOT NULL,
    experience_level text,
    max_people_per_event integer DEFAULT 4,
    hourly_rate numeric(8,2) DEFAULT 135.00,
    is_active boolean DEFAULT true,
    google_calendar_id text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: messages; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.messages (
    topic text NOT NULL,
    extension text NOT NULL,
    payload jsonb,
    event text,
    private boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    inserted_at timestamp without time zone DEFAULT now() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL
)
PARTITION BY RANGE (inserted_at);


--
-- Name: schema_migrations; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.schema_migrations (
    version bigint NOT NULL,
    inserted_at timestamp(0) without time zone
);


--
-- Name: subscription; Type: TABLE; Schema: realtime; Owner: -
--

CREATE TABLE realtime.subscription (
    id bigint NOT NULL,
    subscription_id uuid NOT NULL,
    entity regclass NOT NULL,
    filters realtime.user_defined_filter[] DEFAULT '{}'::realtime.user_defined_filter[] NOT NULL,
    claims jsonb NOT NULL,
    claims_role regrole GENERATED ALWAYS AS (realtime.to_regrole((claims ->> 'role'::text))) STORED NOT NULL,
    created_at timestamp without time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);


--
-- Name: subscription_id_seq; Type: SEQUENCE; Schema: realtime; Owner: -
--

ALTER TABLE realtime.subscription ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME realtime.subscription_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: buckets; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.buckets (
    id text NOT NULL,
    name text NOT NULL,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    public boolean DEFAULT false,
    avif_autodetection boolean DEFAULT false,
    file_size_limit bigint,
    allowed_mime_types text[],
    owner_id text
);


--
-- Name: COLUMN buckets.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.buckets.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: migrations; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.migrations (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    hash character varying(40) NOT NULL,
    executed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: objects; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.objects (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    bucket_id text,
    name text,
    owner uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_accessed_at timestamp with time zone DEFAULT now(),
    metadata jsonb,
    path_tokens text[] GENERATED ALWAYS AS (string_to_array(name, '/'::text)) STORED,
    version text,
    owner_id text,
    user_metadata jsonb
);


--
-- Name: COLUMN objects.owner; Type: COMMENT; Schema: storage; Owner: -
--

COMMENT ON COLUMN storage.objects.owner IS 'Field is deprecated, use owner_id instead';


--
-- Name: s3_multipart_uploads; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.s3_multipart_uploads (
    id text NOT NULL,
    in_progress_size bigint DEFAULT 0 NOT NULL,
    upload_signature text NOT NULL,
    bucket_id text NOT NULL,
    key text NOT NULL COLLATE pg_catalog."C",
    version text NOT NULL,
    owner_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_metadata jsonb
);


--
-- Name: [redacted-token]; Type: TABLE; Schema: storage; Owner: -
--

CREATE TABLE storage.[redacted-token] (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    upload_id text NOT NULL,
    size bigint DEFAULT 0 NOT NULL,
    part_number integer NOT NULL,
    bucket_id text NOT NULL,
    key text NOT NULL COLLATE pg_catalog."C",
    etag text NOT NULL,
    owner_id text,
    version text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: supabase_migrations; Owner: -
--

CREATE TABLE supabase_migrations.schema_migrations (
    version text NOT NULL,
    statements text[],
    name text
);


--
-- Name: seed_files; Type: TABLE; Schema: supabase_migrations; Owner: -
--

CREATE TABLE supabase_migrations.seed_files (
    path text NOT NULL,
    hash text NOT NULL
);


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens ALTER COLUMN id SET DEFAULT nextval('auth.refresh_tokens_id_seq'::regclass);


--
-- Name: activity_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activity_logs ALTER COLUMN id SET DEFAULT nextval('public.activity_logs_id_seq'::regclass);


--
-- Name: payment_method_options id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_method_options ALTER COLUMN id SET DEFAULT nextval('public.[redacted-token]'::regclass);


--
-- Name: payment_status_options id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_status_options ALTER COLUMN id SET DEFAULT nextval('public.[redacted-token]'::regclass);


--
-- Name: status_options id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.status_options ALTER COLUMN id SET DEFAULT nextval('public.status_options_id_seq'::regclass);


--
-- Data for Name: audit_log_entries; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: flow_state; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: identities; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: instances; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: mfa_amr_claims; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: mfa_challenges; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: mfa_factors; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: oauth_clients; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: one_time_tokens; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: refresh_tokens; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: saml_providers; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: saml_relay_states; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: auth; Owner: -
--

INSERT INTO auth.schema_migrations VALUES ('20171026211738');
INSERT INTO auth.schema_migrations VALUES ('20171026211808');
INSERT INTO auth.schema_migrations VALUES ('20171026211834');
INSERT INTO auth.schema_migrations VALUES ('20180103212743');
INSERT INTO auth.schema_migrations VALUES ('20180108183307');
INSERT INTO auth.schema_migrations VALUES ('20180119214651');
INSERT INTO auth.schema_migrations VALUES ('20180125194653');
INSERT INTO auth.schema_migrations VALUES ('00');
INSERT INTO auth.schema_migrations VALUES ('20210710035447');
INSERT INTO auth.schema_migrations VALUES ('20210722035447');
INSERT INTO auth.schema_migrations VALUES ('20210730183235');
INSERT INTO auth.schema_migrations VALUES ('20210909172000');
INSERT INTO auth.schema_migrations VALUES ('20210927181326');
INSERT INTO auth.schema_migrations VALUES ('20211122151130');
INSERT INTO auth.schema_migrations VALUES ('20211124214934');
INSERT INTO auth.schema_migrations VALUES ('20211202183645');
INSERT INTO auth.schema_migrations VALUES ('20220114185221');
INSERT INTO auth.schema_migrations VALUES ('20220114185340');
INSERT INTO auth.schema_migrations VALUES ('20220224000811');
INSERT INTO auth.schema_migrations VALUES ('20220323170000');
INSERT INTO auth.schema_migrations VALUES ('20220429102000');
INSERT INTO auth.schema_migrations VALUES ('20220531120530');
INSERT INTO auth.schema_migrations VALUES ('20220614074223');
INSERT INTO auth.schema_migrations VALUES ('20220811173540');
INSERT INTO auth.schema_migrations VALUES ('20221003041349');
INSERT INTO auth.schema_migrations VALUES ('20221003041400');
INSERT INTO auth.schema_migrations VALUES ('20221011041400');
INSERT INTO auth.schema_migrations VALUES ('20221020193600');
INSERT INTO auth.schema_migrations VALUES ('20221021073300');
INSERT INTO auth.schema_migrations VALUES ('20221021082433');
INSERT INTO auth.schema_migrations VALUES ('20221027105023');
INSERT INTO auth.schema_migrations VALUES ('20221114143122');
INSERT INTO auth.schema_migrations VALUES ('20221114143410');
INSERT INTO auth.schema_migrations VALUES ('20221125140132');
INSERT INTO auth.schema_migrations VALUES ('20221208132122');
INSERT INTO auth.schema_migrations VALUES ('20221215195500');
INSERT INTO auth.schema_migrations VALUES ('20221215195800');
INSERT INTO auth.schema_migrations VALUES ('20221215195900');
INSERT INTO auth.schema_migrations VALUES ('20230116124310');
INSERT INTO auth.schema_migrations VALUES ('20230116124412');
INSERT INTO auth.schema_migrations VALUES ('20230131181311');
INSERT INTO auth.schema_migrations VALUES ('20230322519590');
INSERT INTO auth.schema_migrations VALUES ('20230402418590');
INSERT INTO auth.schema_migrations VALUES ('20230411005111');
INSERT INTO auth.schema_migrations VALUES ('20230508135423');
INSERT INTO auth.schema_migrations VALUES ('20230523124323');
INSERT INTO auth.schema_migrations VALUES ('20230818113222');
INSERT INTO auth.schema_migrations VALUES ('20230914180801');
INSERT INTO auth.schema_migrations VALUES ('20231027141322');
INSERT INTO auth.schema_migrations VALUES ('20231114161723');
INSERT INTO auth.schema_migrations VALUES ('20231117164230');
INSERT INTO auth.schema_migrations VALUES ('20240115144230');
INSERT INTO auth.schema_migrations VALUES ('20240214120130');
INSERT INTO auth.schema_migrations VALUES ('20240306115329');
INSERT INTO auth.schema_migrations VALUES ('20240314092811');
INSERT INTO auth.schema_migrations VALUES ('20240427152123');
INSERT INTO auth.schema_migrations VALUES ('20240612123726');
INSERT INTO auth.schema_migrations VALUES ('20240729123726');
INSERT INTO auth.schema_migrations VALUES ('20240802193726');
INSERT INTO auth.schema_migrations VALUES ('20240806073726');
INSERT INTO auth.schema_migrations VALUES ('20241009103726');
INSERT INTO auth.schema_migrations VALUES ('20250717082212');
INSERT INTO auth.schema_migrations VALUES ('20250731150234');


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: sso_domains; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: sso_providers; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: auth; Owner: -
--



--
-- Data for Name: activity_logs; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.activity_logs VALUES (1, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_initial - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-09 11:36:56+00', '"{\"message_id\":\"1992f2ab9b96fb18\",\"thread_id\":\"1992f2ab9b96fb18\"}"', '2025-09-09 16:28:29.221607+00');
INSERT INTO public.activity_logs VALUES (2, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_initial - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-09 11:36:56+00', '"{\"message_id\":\"1992f2ab9b96fb18\",\"thread_id\":\"1992f2ab9b96fb18\"}"', '2025-09-09 16:30:01.044+00');
INSERT INTO public.activity_logs VALUES (3, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_initial - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-09 19:36:21.315+00', '"{\"message_id\":\"1992ffaa7e70478b\",\"thread_id\":\"1992ffaa7e70478b\"}"', '2025-09-09 19:36:21.642362+00');
INSERT INTO public.activity_logs VALUES (4, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_initial - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-09 19:38:25.487+00', '"{\"message_id\":\"1992ffc8d9dee477\",\"thread_id\":\"1992ffc8d9dee477\"}"', '2025-09-09 19:38:25.622509+00');
INSERT INTO public.activity_logs VALUES (5, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_initial - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-10 11:39:15+00', '"{\"message_id\":\"1993447fa36e6a78\",\"thread_id\":\"1993447fa36e6a78\"}"', '2025-09-10 15:39:17.698+00');
INSERT INTO public.activity_logs VALUES (6, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_initial - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-10 11:39:43+00', '"{\"message_id\":\"1993448682f6c190\",\"thread_id\":\"1993448682f6c190\"}"', '2025-09-10 15:39:45.388+00');
INSERT INTO public.activity_logs VALUES (7, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_initial - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-10 13:58:18+00', '"{\"message_id\":\"19934c747f104d1d\",\"thread_id\":\"19934c747f104d1d\"}"', '2025-09-10 17:58:20.29+00');
INSERT INTO public.activity_logs VALUES (8, 'le-glam-team', 'CUST-1757284936473-XU2N', 'email_sent', 'send_followup - 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'admin', '2025-09-13 09:37:11+00', '"{\"message_id\":\"199434b4d200f570\",\"thread_id\":\"199434b4d200f570\"}"', '2025-09-13 13:37:13.403+00');


--
-- Data for Name: business_settings; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.business_settings VALUES ('[redacted-uuid]', 'le-glam-team', 'LE Glam Team', 'redacted@redacted-handle.com', '[redacted-phone]', '518 U.S. Rte 1, [redacted-address]


--
-- Data for Name: customer_requests; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1756323418476.469973', 'le-glam-team', 'Julie DePerrio', 'redacted@redacted-handle.com', '[redacted-phone]', '2025-09-12', '15:30:00', NULL, 'Cliff House Hotel', 0, 0, NULL, NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-08-27 19:36:58.476333+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-[redacted-phone].690469-13cb', 'le-glam-team', 'Emily Carter', 'redacted@redacted-handle.com', '[redacted-phone]', '2024-02-15', '16:00:00', '10:00:00', 'Marriott Hotel Boston', 2, 4, '', '', 'Instagram', 'Waiting for Payment', 'mama mia', '', NULL, NULL, NULL, NULL, NULL, 675.00, 250.00, 0.00, 'partial', 'cash', NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-08-06 14:01:50.690469+00', '2025-09-16 01:06:48.697137+00', 'hi', NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 675.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-[redacted-phone].[redacted-phone]', 'le-glam-team', 'Sarah Johnson', 'redacted@redacted-handle.com', '[redacted-phone]', '2024-02-20', '14:00:00', NULL, 'The Ritz Carlton', 2, 1, NULL, NULL, NULL, 'Completed', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 270.00, 250.00, 0.00, 'completed', 'stripe', NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-08-06 14:01:50.690469+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 270.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1755053910353.096235', 'le-glam-team', 'Danielle Koca', 'redacted@redacted-handle.com', '[redacted-phone]', '2025-08-27', '14:30:00', NULL, 'Kittery', 0, 0, NULL, NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-08-13 02:58:30.35367+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757038249918-2X55', 'le-glam-team', 'le-glam-team', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 02:10:49.919+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757039458888-DNF7', 'le-glam-team', 'le-glam-team', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 02:30:58.888+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757527047028-K6LW', 'le-glam-team', 'Melissa Smith', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-10 17:57:27.029+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757077795060-DFW0', 'le-glam-team', 'le-glam-team', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', 'Subject: Your Beauty Salon Booking Inquiry – LE Glam Team
 
Dear Melissa Smith,

We are delighted you have chosen LE Glam Team for your special event on November 14, 2025. Thank you for your inquiry. We understand that this is a significant time for you, and we are committed to ensuring that you and your party look absolutely stunning.

According to your request, we have three people each for hair styling and makeup application. Here is your pricing breakdown:

Hair Styling: 3 people x $135 per person = $405 
Makeup Application: 3 people x $135 per person = $405 

With you and your party getting ready at the salon, there are no travel fees involved. Therefore, the total cost for your beauty services on the event day will be $810.

Please note that a non-refundable deposit of $250 is required to secure the date. This deposit will be deducted from your total cost, leaving a balance of $560. Our payment options include checks, Venmo (@redacted-handle), and credit cards.

We are pleased to confirm that we are available on your event day to provide the requested services. Once the deposit is received, we will officially reserve the date and time for you.

We also offer trial runs on Mondays at [redacted-address]

If you have any further inquiries or need additional assistance, feel free to contact us at redacted@redacted-handle.com.

Thank you once again for choosing LE Glam Team. We look forward to serving you and making your day even more special.

Best Regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com
Payment Options: Check, Venmo @redacted-handle, Credit Card', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 13:09:55.06+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757039542303-WJF9', 'le-glam-team', 'le-glam-team', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 02:32:22.303+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757039832611-MLE8', 'le-glam-team', 'le-glam-team', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 02:37:12.611+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757040035524-IGYM', 'le-glam-team', 'le-glam-team', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 02:40:35.524+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757040380390-DI99', 'le-glam-team', 'le-glam-team', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 02:46:20.391+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757080704713-QEKD', 'le-glam-team', 'Melissa Smith', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'New Submission', 'Subject: Your Beauty Booking Inquiry at LE Glam Team

Dear Melissa,

Thank you so much for reaching out to LE Glam Team for your beauty service needs on your special day. We''re thrilled that you''re considering us for your wedding party beauty preparations.

I am pleased to confirm that we are available on your event date, November 14, 2025, and can have your party ready by 3pm as requested.

Here is a breakdown of the services requested and their costs:

- Hair Styling for 3 persons: $135 x 3 = $405
- Makeup Application for 3 persons: $135 x 3 = $405

This brings us to a total of $810. Since your party includes three people, the rate per person is $185, which totals to $555. However, as your booking meets our minimum requirement of 4 services per stylist, you will instead be charged the regular pricing of $810.

As the event location is at our salon, there will be no travel fees incurred. To secure this date and time for your party, a non-refundable deposit of $250 is required.

Next, we would like to recommend our trial run service, which is available on Mondays at [redacted-address]

Once you have decided to proceed with the booking, we can accept your deposit via check, Venmo @redacted-handle, or credit card. Please feel free to reach out to us at redacted@redacted-handle.com if you have any questions or need further clarification. We are here to ensure that your beauty experience is as seamless and enjoyable as possible.

Again, thank you for considering LE Glam Team for your beauty needs. We look forward to adding a touch of glam to your special day!

Best regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com
Payment Options: Check, Venmo @redacted-handle, Credit Card', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-05 13:58:24.713+00', '2025-09-16 01:06:48.697137+00', NULL, NULL, false, NULL, NULL, NULL, NULL, 'America/New_York', NULL, NULL, NULL, NULL, 100, 0.00);
INSERT INTO public.customer_requests VALUES ('[redacted-uuid]', 'CUST-1757284936473-XU2N', 'le-glam-team', 'Melissa Smith', ' redacted@redacted-handle.com', ' [redacted-phone]', '2025-11-14', '15:00:00', NULL, 'at the salon', 3, 3, ' Wedding party, everyone needs to be ready by 3pm', NULL, NULL, 'Email Sent - Awaiting Reply', 'Dear Melissa Smith,

Thank you so much for considering LE Glam Team for your special event on November 14, 2025. We are absolutely thrilled for the opportunity to be a part of your wedding day, and we are pleased to confirm our availability for your requested services.

As per your inquiry, your booking will include styling and makeup application services for three people, all to be completed at our salon. The details are as follows:

- Hair Styling: 3 people x $135 each = $405
- Makeup Application: 3 people x $135 each = $405

This brings the total to $810 for the entire party. As your event will take place at our salon, there will be no travel fees.

Please note that a non-refundable deposit of $250 is required to secure the date. This amount will be deducted from your total payment, leaving a balance of $560 due on the day of service.

For your convenience, we accept payment via check, Venmo (@redacted-handle), and credit card.

We would also like to remind you about our trial run option available on Mondays at [redacted-address]

To move forward with this booking, please reply to this email confirming your acceptance of the total calculated price as well as your preferred method of payment for the deposit. Once we receive this, we will send you a formal agreement to secure your date.

If you have any further questions or need additional information, please don''t hesitate to contact us at redacted@redacted-handle.com. 

Thank you once again for choosing LE Glam Team. We look forward to making your special day even more glamorous!

Best Regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com
', 'Dear Melissa,

Thank you for your thoughtful questions — we’re excited to be part of your big day!

1. For a wedding day appointment at our salon, we typically recommend arriving 15 minutes before your scheduled start time. Once we know your ceremony time, we can work backward to determine the best start time for your group.

2. Yes, we can absolutely add one more person for hair styling. This would bring your total to 4 hair services, which qualifies for our regular rate of $135 per person. The additional service would add $135 to your total.

3. We recommend scheduling your trial run 4–6 weeks before your wedding. Trials are available on Mondays at [redacted-address]

Once you''re ready to proceed, just confirm the updated total and let us know your preferred deposit payment method. We’ll then send over the formal agreement to secure your date.

Best regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com', 'Dear LE Glam Team,
Thank you for getting back to me so quickly. I really appreciate the detailed breakdown of the services.
Before I confirm the booking, I just had a couple of questions:

  1.
How early would we need to arrive at the salon on the wedding day to make sure everything is ready on time?
  2.
Would it be possible to add one more person for just hair styling, and if so, how much would that cost?
  3.
Regarding the trial run — how far in advance would you recommend scheduling it?

Once I have this information, I’ll be ready to move forward with the deposit.
Best,
Melissa Smith


[redacted-token]
From: redacted@redacted-handle.com <redacted@redacted-handle.com>
Sent: Wednesday, September 10, 2025 14:46
To: redacted@redacted-handle.com <redacted@redacted-handle.com>
Subject: 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025

Dear Melissa Smith,

Thank you so much for considering LE Glam Team for your special event
on November 14, 2025. We are absolutely thrilled for the opportunity
to be a part of your wedding day, and we are pleased to confirm our
availability for your requested services.

As per your inquiry, your booking will include styling and makeup
application services for three people, all to be completed at our
salon. The details are as follows:

- Hair Styling: 3 people x $135 each = $405
- Makeup Application: 3 people x $135 each = $405

This brings the total to $810 for the entire party. As your event will
take place at our salon, there will be no travel fees.

Please note that a non-refundable deposit of $250 is required to
secure the date. This amount will be deducted from your total payment,
leaving a balance of $560 due on the day of service.

For your convenience, we accept payment via check, Venmo
(@redacted-handle), and credit card.

We would also like to remind you about our trial run option available
on Mondays at [redacted-address]
your desired looks before the big day.

To move forward with this booking, please reply to this email
confirming your acceptance of the total calculated price as well as
your preferred method of payment for the deposit. Once we receive
this, we will send you a formal agreement to secure your date.

If you have any further questions or need additional information,
please don''t hesitate to contact us at redacted@redacted-handle.com.

Thank you once again for choosing LE Glam Team. We look forward to
making your special day even more glamorous!

Best Regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com

---
This email was sent automatically with n8n
https://n8n.io
', 'Dear Melissa,

Thank you for your thoughtful questions — we’re excited to be part of your big day!

1. For a wedding day appointment at our salon, we typically recommend arriving 15 minutes before your scheduled start time. Once we know your ceremony time, we can work backward to determine the best start time for your group.

2. Yes, we can absolutely add one more person for hair styling. This would bring your total to 4 hair services, which qualifies for our regular rate of $135 per person. The additional service would add $135 to your total.

3. We recommend scheduling your trial run 4–6 weeks before your wedding. Trials are available on Mondays at [redacted-address]

Once you''re ready to proceed, just confirm the updated total and let us know your preferred deposit payment method. We’ll then send over the formal agreement to secure your date.

Best regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com', NULL, 810.00, NULL, NULL, 250.00, 0.00, 'unpaid', NULL, NULL, NULL, 0.00, DEFAULT, DEFAULT, '2025-09-07 22:42:16.473+00', '2025-09-16 01:06:48.697137+00', '🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', NULL, false, NULL, '2025-09-13 09:37:11+00', '2025-09-13 02:16:02.959+00', NULL, 'America/New_York', NULL, '"{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":{\"intent\":\"service_question\",\"urgency\":\"low\",\"key_info\":{\"dates_mentioned\":[\"November 14, 2025\"],\"times_mentioned\":[],\"[redacted-token]\":null,\"[redacted-token]\":\"Add one more person for hair styling only\",\"urgent_matters\":null},\"suggested_action\":\"answer_question\",\"subject_line\":\"Re: Re: 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025\",\"follow_up_draft\":\"Dear Melissa,\\n\\nThank you for your thoughtful questions — we’re excited to be part of your big day!\\n\\n1. For a wedding day appointment at our salon, we typically recommend arriving 15 minutes before your scheduled start time. Once we know your ceremony time, we can work backward to determine the best start time for your group.\\n\\n2. Yes, we can absolutely add one more person for hair styling. This would bring your total to 4 hair services, which qualifies for our regular rate of $135 per person. The additional service would add $135 to your total.\\n\\n3. We recommend scheduling your trial run 4–6 weeks before your wedding. Trials are available on Mondays at [redacted-address]


--
-- Data for Name: email_logs; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.email_logs VALUES ('[redacted-uuid]', 'CUST-1757284936473-XU2N', 'le-glam-team', 'outbound', 'redacted@redacted-handle.com', 'redacted@redacted-handle.com', '🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'Dear Melissa Smith,

Thank you so much for considering LE Glam Team for your special event on November 14, 2025. We are absolutely thrilled for the opportunity to be a part of your wedding day, and we are pleased to confirm our availability for your requested services.

As per your inquiry, your booking will include styling and makeup application services for three people, all to be completed at our salon. The details are as follows:

- Hair Styling: 3 people x $135 each = $405
- Makeup Application: 3 people x $135 each = $405

This brings the total to $810 for the entire party. As your event will take place at our salon, there will be no travel fees.

Please note that a non-refundable deposit of $250 is required to secure the date. This amount will be deducted from your total payment, leaving a balance of $560 due on the day of service.

For your convenience, we accept payment via check, Venmo (@redacted-handle), and credit card.

We would also like to remind you about our trial run option available on Mondays at [redacted-address]

To move forward with this booking, please reply to this email confirming your acceptance of the total calculated price as well as your preferred method of payment for the deposit. Once we receive this, we will send you a formal agreement to secure your date.

If you have any further questions or need additional information, please don''t hesitate to contact us at redacted@redacted-handle.com. 

Thank you once again for choosing LE Glam Team. We look forward to making your special day even more glamorous!

Best Regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com', 'admin', 1, '19934f3883db2b61', '2025-09-10 14:46:39+00', '19934f3883db2b61', NULL, '"{\"Message-ID\":\"19934f3883db2b61\",\"Thread-ID\":\"19934f3883db2b61\"}"', '2025-09-10 18:46:40.24837+00', 'msg_5wa92v_mfebzefq', 'sent', '2025-09-11 15:33:10.641613+00');
INSERT INTO public.email_logs VALUES ('[redacted-uuid]', 'CUST-1757284936473-XU2N', 'le-glam-team', 'inbound', 'redacted@redacted-handle.com', 'redacted@redacted-handle.com', 'Re: 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'Dear LE Glam Team,
Thank you for getting back to me so quickly. I really appreciate the detailed breakdown of the services.
Before I confirm the booking, I just had a couple of questions:

  1.
How early would we need to arrive at the salon on the wedding day to make sure everything is ready on time?
  2.
Would it be possible to add one more person for just hair styling, and if so, how much would that cost?
  3.
Regarding the trial run — how far in advance would you recommend scheduling it?

Once I have this information, I’ll be ready to move forward with the deposit.
Best,
Melissa Smith


[redacted-token]
From: redacted@redacted-handle.com <redacted@redacted-handle.com>
Sent: Wednesday, September 10, 2025 14:46
To: redacted@redacted-handle.com <redacted@redacted-handle.com>
Subject: 🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025

Dear Melissa Smith,

Thank you so much for considering LE Glam Team for your special event
on November 14, 2025. We are absolutely thrilled for the opportunity
to be a part of your wedding day, and we are pleased to confirm our
availability for your requested services.

As per your inquiry, your booking will include styling and makeup
application services for three people, all to be completed at our
salon. The details are as follows:

- Hair Styling: 3 people x $135 each = $405
- Makeup Application: 3 people x $135 each = $405

This brings the total to $810 for the entire party. As your event will
take place at our salon, there will be no travel fees.

Please note that a non-refundable deposit of $250 is required to
secure the date. This amount will be deducted from your total payment,
leaving a balance of $560 due on the day of service.

For your convenience, we accept payment via check, Venmo
(@redacted-handle), and credit card.

We would also like to remind you about our trial run option available
on Mondays at [redacted-address]
your desired looks before the big day.

To move forward with this booking, please reply to this email
confirming your acceptance of the total calculated price as well as
your preferred method of payment for the deposit. Once we receive
this, we will send you a formal agreement to secure your date.

If you have any further questions or need additional information,
please don''t hesitate to contact us at redacted@redacted-handle.com.

Thank you once again for choosing LE Glam Team. We look forward to
making your special day even more glamorous!

Best Regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com

---
This email was sent automatically with n8n
https://n8n.io
', 'customer', 2, '19934f3883db2b61', '2025-09-11 15:59:15.494+00', 'redacted@redacted-handle.com', '<CAHFmkSz2rQKiUSf9_F=bE=AAjO_i1fZpGe+redacted@redacted-handle.com>', NULL, '2025-09-11 15:59:15.630713+00', '[redacted-token]', NULL, '2025-09-11 15:59:15.630713+00');
INSERT INTO public.email_logs VALUES ('[redacted-uuid]', 'CUST-1757284936473-XU2N', 'le-glam-team', 'outbound', 'redacted@redacted-handle.com', 'redacted@redacted-handle.com', '🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'Dear Melissa,

Thank you for your thoughtful questions — we’re excited to be part of your big day!

1. For a wedding day appointment at our salon, we typically recommend arriving 15 minutes before your scheduled start time. Once we know your ceremony time, we can work backward to determine the best start time for your group.

2. Yes, we can absolutely add one more person for hair styling. This would bring your total to 4 hair services, which qualifies for our regular rate of $135 per person. The additional service would add $135 to your total.

3. We recommend scheduling your trial run 4–6 weeks before your wedding. Trials are available on Mondays at [redacted-address]

Once you''re ready to proceed, just confirm the updated total and let us know your preferred deposit payment method. We’ll then send over the formal agreement to secure your date.

Best regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com', 'admin', 3, '1994126a4aa4f6c9', '2025-09-12 23:37:54+00', '1994126a4aa4f6c9', NULL, '"{\"Message-ID\":\"1994126a4aa4f6c9\",\"Thread-ID\":\"1994126a4aa4f6c9\"}"', '2025-09-13 03:37:56.382718+00', 'msg_eqx3ou_mfhpuaw4', 'sent', '2025-09-12 23:37:54+00');
INSERT INTO public.email_logs VALUES ('[redacted-uuid]', 'CUST-1757284936473-XU2N', 'le-glam-team', 'outbound', 'redacted@redacted-handle.com', 'redacted@redacted-handle.com', '🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'Dear Melissa,

Thank you for your thoughtful questions — we’re excited to be part of your big day!

1. For a wedding day appointment at our salon, we typically recommend arriving 15 minutes before your scheduled start time. Once we know your ceremony time, we can work backward to determine the best start time for your group.

2. Yes, we can absolutely add one more person for hair styling. This would bring your total to 4 hair services, which qualifies for our regular rate of $135 per person. The additional service would add $135 to your total.

3. We recommend scheduling your trial run 4–6 weeks before your wedding. Trials are available on Mondays at [redacted-address]

Once you''re ready to proceed, just confirm the updated total and let us know your preferred deposit payment method. We’ll then send over the formal agreement to secure your date.

Best regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com', 'admin', 4, '199433e9b5368af3', '2025-09-13 09:23:19+00', '199433e9b5368af3', NULL, '"{\"Message-ID\":\"199433e9b5368af3\",\"Thread-ID\":\"199433e9b5368af3\"}"', '2025-09-13 13:23:20.878049+00', 'msg_naypee_mfiar5o1', 'sent', '2025-09-13 09:23:19+00');
INSERT INTO public.email_logs VALUES ('[redacted-uuid]', 'CUST-1757284936473-XU2N', 'le-glam-team', 'outbound', 'redacted@redacted-handle.com', 'redacted@redacted-handle.com', '🎉 New Booking at LE Glam — Melissa Smith — Nov 14, 2025', 'Dear Melissa,

Thank you for your thoughtful questions — we’re excited to be part of your big day!

1. For a wedding day appointment at our salon, we typically recommend arriving 15 minutes before your scheduled start time. Once we know your ceremony time, we can work backward to determine the best start time for your group.

2. Yes, we can absolutely add one more person for hair styling. This would bring your total to 4 hair services, which qualifies for our regular rate of $135 per person. The additional service would add $135 to your total.

3. We recommend scheduling your trial run 4–6 weeks before your wedding. Trials are available on Mondays at [redacted-address]

Once you''re ready to proceed, just confirm the updated total and let us know your preferred deposit payment method. We’ll then send over the formal agreement to secure your date.

Best regards,

LE Glam Team
[redacted-address]
redacted@redacted-handle.com', 'admin', 5, '199434b4d200f570', '2025-09-13 09:37:11+00', '199434b4d200f570', NULL, '"{\"Message-ID\":\"199434b4d200f570\",\"Thread-ID\":\"199434b4d200f570\"}"', '2025-09-13 13:37:12.831911+00', 'msg_b1yict_mfib8zn5', 'sent', '2025-09-13 09:37:11+00');


--
-- Data for Name: organizations; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.organizations VALUES ('[redacted-uuid]', 'le-glam-team', 'LE Glam Team', 'leglamteam.com', NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.organizations VALUES ('[redacted-uuid]', 'demo-restaurant', 'Demo Restaurant', 'demo-restaurant.com', NULL, '2025-08-06 14:01:50.690469+00');


--
-- Data for Name: payment_method_options; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.payment_method_options VALUES (1, 'stripe', 'Stripe (Online)', 1);
INSERT INTO public.payment_method_options VALUES (2, 'cash', 'Cash', 2);
INSERT INTO public.payment_method_options VALUES (3, 'bank_transfer', 'Bank Transfer', 3);
INSERT INTO public.payment_method_options VALUES (4, 'phone_payment', 'Phone Payment', 4);
INSERT INTO public.payment_method_options VALUES (5, 'venmo', 'Venmo', 5);
INSERT INTO public.payment_method_options VALUES (6, 'zelle', 'Zelle', 6);
INSERT INTO public.payment_method_options VALUES (7, 'check', 'Check', 7);


--
-- Data for Name: payment_status_options; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.payment_status_options VALUES (1, 'pending', 'Pending', 1);
INSERT INTO public.payment_status_options VALUES (2, 'partial', 'Partial Payment', 2);
INSERT INTO public.payment_status_options VALUES (3, 'completed', 'Completed', 3);
INSERT INTO public.payment_status_options VALUES (4, 'refunded', 'Refunded', 4);
INSERT INTO public.payment_status_options VALUES (5, 'unpaid', 'Unpaid', 0);


--
-- Data for Name: pricing_rules; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.pricing_rules VALUES ('[redacted-uuid]', 'le-glam-team', 'hair', 135.00, 135.00, 0.75, 40.00, 50.00, 100, 1.00, 1.00, 250.00, true, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.pricing_rules VALUES ('[redacted-uuid]', 'le-glam-team', 'makeup', 135.00, 135.00, 0.75, 40.00, 50.00, 100, 1.00, 1.00, 250.00, true, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.pricing_rules VALUES ('[redacted-uuid]', 'le-glam-team', 'both', 270.00, 270.00, 0.75, 40.00, 50.00, 100, 1.00, 1.00, 250.00, true, '2025-08-06 14:01:50.690469+00');


--
-- Data for Name: request_stylists; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.request_stylists VALUES ('[redacted-uuid]', '[redacted-uuid]', '[redacted-uuid]', '2025-08-27 19:16:45.017531+00', 'le-glam-team', 'Jessica Brown', 'redacted@redacted-handle.com');
INSERT INTO public.request_stylists VALUES ('[redacted-uuid]', '[redacted-uuid]', '[redacted-uuid]', '2025-08-27 19:20:31.357534+00', 'le-glam-team', 'Ashley Kim', 'redacted@redacted-handle.com');
INSERT INTO public.request_stylists VALUES ('[redacted-uuid]', '[redacted-uuid]', '[redacted-uuid]', '2025-08-27 19:20:31.357534+00', 'le-glam-team', 'Maria Garcia', 'redacted@redacted-handle.com');
INSERT INTO public.request_stylists VALUES ('[redacted-uuid]', '[redacted-uuid]', '[redacted-uuid]', '2025-08-27 19:20:31.357534+00', 'le-glam-team', 'Jessica Brown', 'redacted@redacted-handle.com');
INSERT INTO public.request_stylists VALUES ('[redacted-uuid]', '[redacted-uuid]', '[redacted-uuid]', '2025-08-27 19:20:31.357534+00', 'le-glam-team', 'Sarah Johnson', 'redacted@redacted-handle.com');
INSERT INTO public.request_stylists VALUES ('[redacted-uuid]', '[redacted-uuid]', '[redacted-uuid]', '2025-09-16 23:52:49.381452+00', 'le-glam-team', 'Ashley Kim', 'redacted@redacted-handle.com');


--
-- Data for Name: status_options; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.status_options VALUES (1, 'New Submission', 'New Submission', 1);
INSERT INTO public.status_options VALUES (2, 'Email Sent - Awaiting Reply', 'Email Sent - Awaiting Reply', 2);
INSERT INTO public.status_options VALUES (3, 'Customer Replied', 'Customer Replied', 3);
INSERT INTO public.status_options VALUES (4, 'Waiting for Payment', 'Waiting for Payment', 4);
INSERT INTO public.status_options VALUES (5, 'Payment Received - Confirmed Email Sent', 'Payment Received - Confirmed Email Sent', 5);
INSERT INTO public.status_options VALUES (6, 'Completed', 'Completed', 6);
INSERT INTO public.status_options VALUES (7, 'Cancelled', 'Cancelled', 7);


--
-- Data for Name: stylist_availability; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-06', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-07', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-08', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-09', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-10', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-11', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-12', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-13', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-14', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-15', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-16', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-17', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-18', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-19', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-20', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-21', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-22', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-23', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-24', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-25', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-26', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-27', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-28', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-29', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-30', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-31', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-01', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-02', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-03', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-04', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-05', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-06', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-07', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-08', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-09', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-10', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-11', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-12', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-13', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-14', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-15', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-16', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-17', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-18', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-19', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-20', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-21', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-22', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-23', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-24', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-25', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-26', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-27', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-28', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-29', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-30', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-31', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-01', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-02', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-03', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-04', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-05', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-06', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-07', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-08', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-09', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-10', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-11', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-12', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-13', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-14', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-15', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-16', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-17', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-18', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-19', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-20', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-21', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-22', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-23', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-24', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-25', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-26', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-27', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-28', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-29', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-30', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-31', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-01', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-02', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-03', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-04', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-05', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-06', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-07', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-08', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-09', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-10', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-11', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-12', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-13', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-14', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-15', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-16', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-17', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-18', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-19', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-20', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-21', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-22', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-23', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-24', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-25', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-26', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-27', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-28', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-29', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-30', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-08-31', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-01', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-02', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-03', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-04', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');
INSERT INTO public.stylist_availability VALUES ('[redacted-uuid]', '[redacted-uuid]', '2025-09-05', '08:00:00', '18:00:00', false, NULL, '2025-08-06 14:01:50.690469+00');


--
-- Data for Name: stylists; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.stylists VALUES ('[redacted-uuid]', 'le-glam-team', 'Sarah Johnson', 'redacted@redacted-handle.com', NULL, 'hair', 'senior', 4, 135.00, true, NULL, '2025-08-06 14:01:50.690469+00', '2025-09-08 21:09:52.706496+00');
INSERT INTO public.stylists VALUES ('[redacted-uuid]', 'le-glam-team', 'Maria Garcia', 'redacted@redacted-handle.com', NULL, 'makeup', 'senior', 4, 135.00, true, NULL, '2025-08-06 14:01:50.690469+00', '2025-09-08 21:09:52.706496+00');
INSERT INTO public.stylists VALUES ('[redacted-uuid]', 'le-glam-team', 'Ashley Kim', 'redacted@redacted-handle.com', NULL, 'both', 'lead', 4, 135.00, true, NULL, '2025-08-06 14:01:50.690469+00', '2025-09-08 21:09:52.706496+00');
INSERT INTO public.stylists VALUES ('[redacted-uuid]', 'le-glam-team', 'Jessica Brown', 'redacted@redacted-handle.com', NULL, 'hair', 'junior', 4, 135.00, true, NULL, '2025-08-06 14:01:50.690469+00', '2025-09-08 21:09:52.706496+00');
INSERT INTO public.stylists VALUES ('[redacted-uuid]', 'le-glam-team', 'Emily Carter', 'redacted@redacted-handle.com', NULL, 'both', 'senior', 4, 135.00, true, NULL, '2025-09-02 14:26:40.60369+00', '2025-09-08 21:09:52.706496+00');


--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: realtime; Owner: -
--

INSERT INTO realtime.schema_migrations VALUES (20211116024918, '2025-08-06 13:47:09');
INSERT INTO realtime.schema_migrations VALUES (20211116045059, '2025-08-06 13:47:12');
INSERT INTO realtime.schema_migrations VALUES (20211116050929, '2025-08-06 13:47:14');
INSERT INTO realtime.schema_migrations VALUES (20211116051442, '2025-08-06 13:47:16');
INSERT INTO realtime.schema_migrations VALUES (20211116212300, '2025-08-06 13:47:19');
INSERT INTO realtime.schema_migrations VALUES (20211116213355, '2025-08-06 13:47:21');
INSERT INTO realtime.schema_migrations VALUES (20211116213934, '2025-08-06 13:47:23');
INSERT INTO realtime.schema_migrations VALUES (20211116214523, '2025-08-06 13:47:26');
INSERT INTO realtime.schema_migrations VALUES (20211122062447, '2025-08-06 13:47:29');
INSERT INTO realtime.schema_migrations VALUES (20211124070109, '2025-08-06 13:47:31');
INSERT INTO realtime.schema_migrations VALUES (20211202204204, '2025-08-06 13:47:33');
INSERT INTO realtime.schema_migrations VALUES (20211202204605, '2025-08-06 13:47:35');
INSERT INTO realtime.schema_migrations VALUES (20211210212804, '2025-08-06 13:47:42');
INSERT INTO realtime.schema_migrations VALUES (20211228014915, '2025-08-06 13:47:44');
INSERT INTO realtime.schema_migrations VALUES (20220107221237, '2025-08-06 13:47:47');
INSERT INTO realtime.schema_migrations VALUES (20220228202821, '2025-08-06 13:47:49');
INSERT INTO realtime.schema_migrations VALUES (20220312004840, '2025-08-06 13:47:51');
INSERT INTO realtime.schema_migrations VALUES (20220603231003, '2025-08-06 13:47:55');
INSERT INTO realtime.schema_migrations VALUES (20220603232444, '2025-08-06 13:47:57');
INSERT INTO realtime.schema_migrations VALUES (20220615214548, '2025-08-06 13:47:59');
INSERT INTO realtime.schema_migrations VALUES (20220712093339, '2025-08-06 13:48:02');
INSERT INTO realtime.schema_migrations VALUES (20220908172859, '2025-08-06 13:48:04');
INSERT INTO realtime.schema_migrations VALUES (20220916233421, '2025-08-06 13:48:06');
INSERT INTO realtime.schema_migrations VALUES (20230119133233, '2025-08-06 13:48:08');
INSERT INTO realtime.schema_migrations VALUES (20230128025114, '2025-08-06 13:48:11');
INSERT INTO realtime.schema_migrations VALUES (20230128025212, '2025-08-06 13:48:13');
INSERT INTO realtime.schema_migrations VALUES (20230227211149, '2025-08-06 13:48:16');
INSERT INTO realtime.schema_migrations VALUES (20230228184745, '2025-08-06 13:48:18');
INSERT INTO realtime.schema_migrations VALUES (20230308225145, '2025-08-06 13:48:20');
INSERT INTO realtime.schema_migrations VALUES (20230328144023, '2025-08-06 13:48:22');
INSERT INTO realtime.schema_migrations VALUES (20231018144023, '2025-08-06 13:48:25');
INSERT INTO realtime.schema_migrations VALUES (20231204144023, '2025-08-06 13:48:28');
INSERT INTO realtime.schema_migrations VALUES (20231204144024, '2025-08-06 13:48:31');
INSERT INTO realtime.schema_migrations VALUES (20231204144025, '2025-08-06 13:48:33');
INSERT INTO realtime.schema_migrations VALUES (20240108234812, '2025-08-06 13:48:35');
INSERT INTO realtime.schema_migrations VALUES (20240109165339, '2025-08-06 13:48:37');
INSERT INTO realtime.schema_migrations VALUES (20240227174441, '2025-08-06 13:48:41');
INSERT INTO realtime.schema_migrations VALUES (20240311171622, '2025-08-06 13:48:44');
INSERT INTO realtime.schema_migrations VALUES (20240321100241, '2025-08-06 13:48:49');
INSERT INTO realtime.schema_migrations VALUES (20240401105812, '2025-08-06 13:48:55');
INSERT INTO realtime.schema_migrations VALUES (20240418121054, '2025-08-06 13:48:58');
INSERT INTO realtime.schema_migrations VALUES (20240523004032, '2025-08-06 13:49:06');
INSERT INTO realtime.schema_migrations VALUES (20240618124746, '2025-08-06 13:49:08');
INSERT INTO realtime.schema_migrations VALUES (20240801235015, '2025-08-06 13:49:11');
INSERT INTO realtime.schema_migrations VALUES (20240805133720, '2025-08-06 13:49:13');
INSERT INTO realtime.schema_migrations VALUES (20240827160934, '2025-08-06 13:49:15');
INSERT INTO realtime.schema_migrations VALUES (20240919163303, '2025-08-06 13:49:18');
INSERT INTO realtime.schema_migrations VALUES (20240919163305, '2025-08-06 13:49:20');
INSERT INTO realtime.schema_migrations VALUES (20241019105805, '2025-08-06 13:49:22');
INSERT INTO realtime.schema_migrations VALUES (20241030150047, '2025-08-06 13:49:31');
INSERT INTO realtime.schema_migrations VALUES (20241108114728, '2025-08-06 13:49:34');
INSERT INTO realtime.schema_migrations VALUES (20241121104152, '2025-08-06 13:49:36');
INSERT INTO realtime.schema_migrations VALUES (20241130184212, '2025-08-06 13:49:39');
INSERT INTO realtime.schema_migrations VALUES (20241220035512, '2025-08-06 13:49:41');
INSERT INTO realtime.schema_migrations VALUES (20241220123912, '2025-08-06 13:49:43');
INSERT INTO realtime.schema_migrations VALUES (20241224161212, '2025-08-06 13:49:45');
INSERT INTO realtime.schema_migrations VALUES (20250107150512, '2025-08-06 13:49:48');
INSERT INTO realtime.schema_migrations VALUES (20250110162412, '2025-08-06 13:49:50');
INSERT INTO realtime.schema_migrations VALUES (20250123174212, '2025-08-06 13:49:52');
INSERT INTO realtime.schema_migrations VALUES (20250128220012, '2025-08-06 13:49:54');
INSERT INTO realtime.schema_migrations VALUES (20250506224012, '2025-08-06 13:49:56');
INSERT INTO realtime.schema_migrations VALUES (20250523164012, '2025-08-06 13:49:58');
INSERT INTO realtime.schema_migrations VALUES (20250714121412, '2025-08-06 13:50:00');


--
-- Data for Name: subscription; Type: TABLE DATA; Schema: realtime; Owner: -
--



--
-- Data for Name: buckets; Type: TABLE DATA; Schema: storage; Owner: -
--



--
-- Data for Name: migrations; Type: TABLE DATA; Schema: storage; Owner: -
--

INSERT INTO storage.migrations VALUES (0, 'create-migrations-table', '[redacted-token]', '2025-08-06 13:47:05.390223');
INSERT INTO storage.migrations VALUES (1, 'initialmigration', '[redacted-token]', '2025-08-06 13:47:05.399486');
INSERT INTO storage.migrations VALUES (2, 'storage-schema', '[redacted-token]', '2025-08-06 13:47:05.407868');
INSERT INTO storage.migrations VALUES (3, 'pathtoken-column', '[redacted-token]', '2025-08-06 13:47:05.490397');
INSERT INTO storage.migrations VALUES (4, 'add-migrations-rls', '[redacted-token]', '2025-08-06 13:47:05.816808');
INSERT INTO storage.migrations VALUES (5, 'add-size-functions', '[redacted-token]', '2025-08-06 13:47:05.821499');
INSERT INTO storage.migrations VALUES (6, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.827874');
INSERT INTO storage.migrations VALUES (7, 'add-rls-to-buckets', '[redacted-token]', '2025-08-06 13:47:05.832036');
INSERT INTO storage.migrations VALUES (8, 'add-public-to-buckets', '[redacted-token]', '2025-08-06 13:47:05.836354');
INSERT INTO storage.migrations VALUES (9, 'fix-search-function', '[redacted-token]', '2025-08-06 13:47:05.840219');
INSERT INTO storage.migrations VALUES (10, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.846475');
INSERT INTO storage.migrations VALUES (11, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.850023');
INSERT INTO storage.migrations VALUES (12, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.886322');
INSERT INTO storage.migrations VALUES (13, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.889796');
INSERT INTO storage.migrations VALUES (14, 'use-bytes-for-max-size', '[redacted-token]', '2025-08-06 13:47:05.897983');
INSERT INTO storage.migrations VALUES (15, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.941118');
INSERT INTO storage.migrations VALUES (16, 'add-version', '[redacted-token]', '2025-08-06 13:47:05.944735');
INSERT INTO storage.migrations VALUES (17, 'drop-owner-foreign-key', '[redacted-token]', '2025-08-06 13:47:05.947938');
INSERT INTO storage.migrations VALUES (18, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.958843');
INSERT INTO storage.migrations VALUES (19, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.975515');
INSERT INTO storage.migrations VALUES (20, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:05.978814');
INSERT INTO storage.migrations VALUES (21, 's3-multipart-uploads', '[redacted-token]', '2025-08-06 13:47:05.984287');
INSERT INTO storage.migrations VALUES (22, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:06.026175');
INSERT INTO storage.migrations VALUES (23, '[redacted-token]', '[redacted-token]', '2025-08-06 13:47:06.063063');
INSERT INTO storage.migrations VALUES (24, 'operation-function', '[redacted-token]', '2025-08-06 13:47:06.072957');
INSERT INTO storage.migrations VALUES (25, 'custom-metadata', '[redacted-token]', '2025-08-06 13:47:06.079698');


--
-- Data for Name: objects; Type: TABLE DATA; Schema: storage; Owner: -
--



--
-- Data for Name: s3_multipart_uploads; Type: TABLE DATA; Schema: storage; Owner: -
--



--
-- Data for Name: [redacted-token]; Type: TABLE DATA; Schema: storage; Owner: -
--



--
-- Data for Name: schema_migrations; Type: TABLE DATA; Schema: supabase_migrations; Owner: -
--



--
-- Data for Name: seed_files; Type: TABLE DATA; Schema: supabase_migrations; Owner: -
--



--
-- Data for Name: secrets; Type: TABLE DATA; Schema: vault; Owner: -
--



--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE SET; Schema: auth; Owner: -
--

SELECT pg_catalog.setval('auth.refresh_tokens_id_seq', 1, false);


--
-- Name: activity_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.activity_logs_id_seq', 8, true);


--
-- Name: [redacted-token]; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.[redacted-token]', 7, true);


--
-- Name: [redacted-token]; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.[redacted-token]', 7, true);


--
-- Name: status_options_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.status_options_id_seq', 7, true);


--
-- Name: subscription_id_seq; Type: SEQUENCE SET; Schema: realtime; Owner: -
--

SELECT pg_catalog.setval('realtime.subscription_id_seq', 1, false);


--
-- Name: mfa_amr_claims amr_id_pk; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT amr_id_pk PRIMARY KEY (id);


--
-- Name: audit_log_entries audit_log_entries_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.audit_log_entries
    ADD CONSTRAINT audit_log_entries_pkey PRIMARY KEY (id);


--
-- Name: flow_state flow_state_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.flow_state
    ADD CONSTRAINT flow_state_pkey PRIMARY KEY (id);


--
-- Name: identities identities_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_pkey PRIMARY KEY (id);


--
-- Name: identities [redacted-token]; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT [redacted-token] UNIQUE (provider_id, provider);


--
-- Name: instances instances_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.instances
    ADD CONSTRAINT instances_pkey PRIMARY KEY (id);


--
-- Name: mfa_amr_claims [redacted-token]; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT [redacted-token] UNIQUE (session_id, authentication_method);


--
-- Name: mfa_challenges mfa_challenges_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT mfa_challenges_pkey PRIMARY KEY (id);


--
-- Name: mfa_factors [redacted-token]; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT [redacted-token] UNIQUE (last_challenged_at);


--
-- Name: mfa_factors mfa_factors_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT mfa_factors_pkey PRIMARY KEY (id);


--
-- Name: oauth_clients [redacted-token]; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_clients
    ADD CONSTRAINT [redacted-token] UNIQUE (client_id);


--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: one_time_tokens one_time_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.one_time_tokens
    ADD CONSTRAINT one_time_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens [redacted-token]; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT [redacted-token] UNIQUE (token);


--
-- Name: saml_providers [redacted-token]; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT [redacted-token] UNIQUE (entity_id);


--
-- Name: saml_providers saml_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT saml_providers_pkey PRIMARY KEY (id);


--
-- Name: saml_relay_states saml_relay_states_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT saml_relay_states_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sso_domains sso_domains_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT sso_domains_pkey PRIMARY KEY (id);


--
-- Name: sso_providers sso_providers_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_providers
    ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);


--
-- Name: users users_phone_key; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_phone_key UNIQUE (phone);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: activity_logs activity_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activity_logs
    ADD CONSTRAINT activity_logs_pkey PRIMARY KEY (id);


--
-- Name: business_settings [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.business_settings
    ADD CONSTRAINT [redacted-token] UNIQUE (org_id);


--
-- Name: business_settings business_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.business_settings
    ADD CONSTRAINT business_settings_pkey PRIMARY KEY (id);


--
-- Name: customer_requests [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_requests
    ADD CONSTRAINT [redacted-token] UNIQUE (customer_id);


--
-- Name: customer_requests customer_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_requests
    ADD CONSTRAINT customer_requests_pkey PRIMARY KEY (id);


--
-- Name: email_logs email_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_logs
    ADD CONSTRAINT email_logs_pkey PRIMARY KEY (id);


--
-- Name: organizations [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT [redacted-token] UNIQUE (org_id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: payment_method_options [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_method_options
    ADD CONSTRAINT [redacted-token] PRIMARY KEY (id);


--
-- Name: payment_method_options [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_method_options
    ADD CONSTRAINT [redacted-token] UNIQUE (value);


--
-- Name: payment_status_options [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_status_options
    ADD CONSTRAINT [redacted-token] PRIMARY KEY (id);


--
-- Name: payment_status_options [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payment_status_options
    ADD CONSTRAINT [redacted-token] UNIQUE (value);


--
-- Name: pricing_rules pricing_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pricing_rules
    ADD CONSTRAINT pricing_rules_pkey PRIMARY KEY (id);


--
-- Name: request_stylists request_stylists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_stylists
    ADD CONSTRAINT request_stylists_pkey PRIMARY KEY (id);


--
-- Name: request_stylists [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_stylists
    ADD CONSTRAINT [redacted-token] UNIQUE (request_id, stylist_id);


--
-- Name: status_options status_options_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.status_options
    ADD CONSTRAINT status_options_pkey PRIMARY KEY (id);


--
-- Name: status_options [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.status_options
    ADD CONSTRAINT [redacted-token] UNIQUE (value);


--
-- Name: stylist_availability [redacted-token]; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stylist_availability
    ADD CONSTRAINT [redacted-token] PRIMARY KEY (id);


--
-- Name: stylists stylists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stylists
    ADD CONSTRAINT stylists_pkey PRIMARY KEY (id);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id, inserted_at);


--
-- Name: subscription pk_subscription; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.subscription
    ADD CONSTRAINT pk_subscription PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: realtime; Owner: -
--

ALTER TABLE ONLY realtime.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: buckets buckets_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.buckets
    ADD CONSTRAINT buckets_pkey PRIMARY KEY (id);


--
-- Name: migrations migrations_name_key; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_name_key UNIQUE (name);


--
-- Name: migrations migrations_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.migrations
    ADD CONSTRAINT migrations_pkey PRIMARY KEY (id);


--
-- Name: objects objects_pkey; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT objects_pkey PRIMARY KEY (id);


--
-- Name: [redacted-token] [redacted-token]; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.[redacted-token]
    ADD CONSTRAINT [redacted-token] PRIMARY KEY (id);


--
-- Name: s3_multipart_uploads [redacted-token]; Type: CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads
    ADD CONSTRAINT [redacted-token] PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: supabase_migrations; Owner: -
--

ALTER TABLE ONLY supabase_migrations.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: seed_files seed_files_pkey; Type: CONSTRAINT; Schema: supabase_migrations; Owner: -
--

ALTER TABLE ONLY supabase_migrations.seed_files
    ADD CONSTRAINT seed_files_pkey PRIMARY KEY (path);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.audit_log_entries USING btree (instance_id);


--
-- Name: confirmation_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX confirmation_token_idx ON auth.users USING btree (confirmation_token) WHERE ((confirmation_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON auth.users USING btree ([redacted-token]) WHERE (([redacted-token])::text !~ '^[0-9 ]*$'::text);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON auth.users USING btree (email_change_token_new) WHERE ((email_change_token_new)::text !~ '^[0-9 ]*$'::text);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.mfa_factors USING btree (user_id, created_at);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.flow_state USING btree (created_at DESC);


--
-- Name: identities_email_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_email_idx ON auth.identities USING btree (email text_pattern_ops);


--
-- Name: INDEX identities_email_idx; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.identities_email_idx IS 'Auth: Ensures indexed queries on the email column';


--
-- Name: identities_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX identities_user_id_idx ON auth.identities USING btree (user_id);


--
-- Name: idx_auth_code; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_auth_code ON auth.flow_state USING btree (auth_code);


--
-- Name: idx_user_id_auth_method; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX idx_user_id_auth_method ON auth.flow_state USING btree (user_id, authentication_method);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.mfa_challenges USING btree (created_at DESC);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON auth.mfa_factors USING btree (friendly_name, user_id) WHERE (TRIM(BOTH FROM friendly_name) <> ''::text);


--
-- Name: mfa_factors_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX mfa_factors_user_id_idx ON auth.mfa_factors USING btree (user_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.oauth_clients USING btree (client_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.oauth_clients USING btree (deleted_at);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.one_time_tokens USING hash (relates_to);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.one_time_tokens USING hash (token_hash);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON auth.one_time_tokens USING btree (user_id, token_type);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON auth.users USING btree (reauthentication_token) WHERE ((reauthentication_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: recovery_token_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX recovery_token_idx ON auth.users USING btree (recovery_token) WHERE ((recovery_token)::text !~ '^[0-9 ]*$'::text);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.refresh_tokens USING btree (instance_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.refresh_tokens USING btree (instance_id, user_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.refresh_tokens USING btree (parent);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.refresh_tokens USING btree (session_id, revoked);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.refresh_tokens USING btree (updated_at DESC);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.saml_providers USING btree (sso_provider_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.saml_relay_states USING btree (created_at DESC);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.saml_relay_states USING btree (for_email);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.saml_relay_states USING btree (sso_provider_id);


--
-- Name: sessions_not_after_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_not_after_idx ON auth.sessions USING btree (not_after DESC);


--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX sessions_user_id_idx ON auth.sessions USING btree (user_id);


--
-- Name: sso_domains_domain_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX sso_domains_domain_idx ON auth.sso_domains USING btree (lower(domain));


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.sso_domains USING btree (sso_provider_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON auth.sso_providers USING btree (lower(resource_id));


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.sso_providers USING btree (resource_id text_pattern_ops);


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON auth.mfa_factors USING btree (user_id, phone);


--
-- Name: user_id_created_at_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX user_id_created_at_idx ON auth.sessions USING btree (user_id, created_at);


--
-- Name: users_email_partial_key; Type: INDEX; Schema: auth; Owner: -
--

CREATE UNIQUE INDEX users_email_partial_key ON auth.users USING btree (email) WHERE (is_sso_user = false);


--
-- Name: INDEX users_email_partial_key; Type: COMMENT; Schema: auth; Owner: -
--

COMMENT ON INDEX auth.users_email_partial_key IS 'Auth: A partial unique index that applies only when is_sso_user is false';


--
-- Name: [redacted-token]; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX [redacted-token] ON auth.users USING btree (instance_id, lower((email)::text));


--
-- Name: users_instance_id_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_instance_id_idx ON auth.users USING btree (instance_id);


--
-- Name: users_is_anonymous_idx; Type: INDEX; Schema: auth; Owner: -
--

CREATE INDEX users_is_anonymous_idx ON auth.users USING btree (is_anonymous);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.activity_logs USING btree (action);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.activity_logs USING btree (customer_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.activity_logs USING btree ("timestamp" DESC);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON public.email_logs USING btree (client_message_id);


--
-- Name: email_logs_thread_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_logs_thread_idx ON public.email_logs USING btree (thread_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.customer_requests USING btree (customer_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.customer_requests USING btree (event_date);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.customer_requests USING btree (customer_email);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.customer_requests USING btree (org_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.customer_requests USING btree (payment_status);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.customer_requests USING btree (current_status);


--
-- Name: idx_email_logs_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_email_logs_customer ON public.email_logs USING btree (customer_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.email_logs USING btree (in_reply_to);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.email_logs USING btree (message_id);


--
-- Name: idx_email_logs_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_email_logs_org ON public.email_logs USING btree (org_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.email_logs USING btree ("timestamp");


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.request_stylists USING btree (request_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.request_stylists USING btree (stylist_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.stylist_availability USING btree (available_date);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.stylist_availability USING btree (stylist_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX [redacted-token] ON public.request_stylists USING btree (org_id, request_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON public.request_stylists USING btree (request_id, stylist_id);


--
-- Name: [redacted-token]; Type: INDEX; Schema: realtime; Owner: -
--

CREATE INDEX [redacted-token] ON realtime.subscription USING btree (entity);


--
-- Name: [redacted-token]; Type: INDEX; Schema: realtime; Owner: -
--

CREATE UNIQUE INDEX [redacted-token] ON realtime.subscription USING btree (subscription_id, entity, filters);


--
-- Name: bname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bname ON storage.buckets USING btree (name);


--
-- Name: bucketid_objname; Type: INDEX; Schema: storage; Owner: -
--

CREATE UNIQUE INDEX bucketid_objname ON storage.objects USING btree (bucket_id, name);


--
-- Name: [redacted-token]; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX [redacted-token] ON storage.s3_multipart_uploads USING btree (bucket_id, key, created_at);


--
-- Name: [redacted-token]; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX [redacted-token] ON storage.objects USING btree (bucket_id, name COLLATE "C");


--
-- Name: name_prefix_search; Type: INDEX; Schema: storage; Owner: -
--

CREATE INDEX name_prefix_search ON storage.objects USING btree (name text_pattern_ops);


--
-- Name: email_logs set_email_sequence; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_email_sequence BEFORE INSERT ON public.email_logs FOR EACH ROW EXECUTE FUNCTION public.[redacted-token]();


--
-- Name: request_stylists trg_rs_fill; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_rs_fill BEFORE INSERT OR UPDATE OF request_id, stylist_id ON public.request_stylists FOR EACH ROW EXECUTE FUNCTION public.[redacted-token]();


--
-- Name: stylists [redacted-token]; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER [redacted-token] AFTER UPDATE OF name, email ON public.stylists FOR EACH ROW EXECUTE FUNCTION public.[redacted-token]();


--
-- Name: business_settings [redacted-token]; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER [redacted-token] BEFORE UPDATE ON public.business_settings FOR EACH ROW EXECUTE FUNCTION public.[redacted-token]();


--
-- Name: customer_requests [redacted-token]; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER [redacted-token] BEFORE UPDATE ON public.customer_requests FOR EACH ROW EXECUTE FUNCTION public.[redacted-token]();


--
-- Name: email_logs [redacted-token]; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER [redacted-token] BEFORE UPDATE ON public.email_logs FOR EACH ROW EXECUTE FUNCTION public.[redacted-token]();


--
-- Name: stylists [redacted-token]; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER [redacted-token] BEFORE UPDATE ON public.stylists FOR EACH ROW EXECUTE FUNCTION public.[redacted-token]();


--
-- Name: subscription tr_check_filters; Type: TRIGGER; Schema: realtime; Owner: -
--

CREATE TRIGGER tr_check_filters BEFORE INSERT OR UPDATE ON realtime.subscription FOR EACH ROW EXECUTE FUNCTION realtime.[redacted-token]();


--
-- Name: objects [redacted-token]; Type: TRIGGER; Schema: storage; Owner: -
--

CREATE TRIGGER [redacted-token] BEFORE UPDATE ON storage.objects FOR EACH ROW EXECUTE FUNCTION storage.[redacted-token]();


--
-- Name: identities identities_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.identities
    ADD CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: mfa_amr_claims [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_amr_claims
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: mfa_challenges [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_challenges
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (factor_id) REFERENCES auth.mfa_factors(id) ON DELETE CASCADE;


--
-- Name: mfa_factors [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.mfa_factors
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: one_time_tokens [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.one_time_tokens
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.refresh_tokens
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (session_id) REFERENCES auth.sessions(id) ON DELETE CASCADE;


--
-- Name: saml_providers [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_providers
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (flow_state_id) REFERENCES auth.flow_state(id) ON DELETE CASCADE;


--
-- Name: saml_relay_states [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.saml_relay_states
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;


--
-- Name: sso_domains [redacted-token]; Type: FK CONSTRAINT; Schema: auth; Owner: -
--

ALTER TABLE ONLY auth.sso_domains
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (sso_provider_id) REFERENCES auth.sso_providers(id) ON DELETE CASCADE;


--
-- Name: business_settings [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.business_settings
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (org_id) REFERENCES public.organizations(org_id);


--
-- Name: customer_requests [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_requests
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (org_id) REFERENCES public.organizations(org_id);


--
-- Name: email_logs [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_logs
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (customer_id) REFERENCES public.customer_requests(customer_id) ON DELETE CASCADE;


--
-- Name: email_logs email_logs_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_logs
    ADD CONSTRAINT email_logs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(org_id);


--
-- Name: customer_requests fk_payment_method; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_requests
    ADD CONSTRAINT fk_payment_method FOREIGN KEY (payment_method) REFERENCES public.payment_method_options(value) ON UPDATE CASCADE;


--
-- Name: customer_requests fk_payment_status; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_requests
    ADD CONSTRAINT fk_payment_status FOREIGN KEY (payment_status) REFERENCES public.payment_status_options(value) ON UPDATE CASCADE;


--
-- Name: request_stylists fk_rs_org; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_stylists
    ADD CONSTRAINT fk_rs_org FOREIGN KEY (org_id) REFERENCES public.organizations(org_id) ON DELETE CASCADE;


--
-- Name: request_stylists fk_rs_req; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_stylists
    ADD CONSTRAINT fk_rs_req FOREIGN KEY (request_id) REFERENCES public.customer_requests(id) ON DELETE CASCADE;


--
-- Name: request_stylists fk_rs_sty; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_stylists
    ADD CONSTRAINT fk_rs_sty FOREIGN KEY (stylist_id) REFERENCES public.stylists(id) ON DELETE CASCADE;


--
-- Name: customer_requests fk_status; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_requests
    ADD CONSTRAINT fk_status FOREIGN KEY (current_status) REFERENCES public.status_options(value) ON UPDATE CASCADE;


--
-- Name: pricing_rules [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pricing_rules
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (org_id) REFERENCES public.organizations(org_id);


--
-- Name: request_stylists [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_stylists
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (request_id) REFERENCES public.customer_requests(id) ON DELETE CASCADE;


--
-- Name: request_stylists [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.request_stylists
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (stylist_id) REFERENCES public.stylists(id) ON DELETE RESTRICT;


--
-- Name: stylist_availability [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stylist_availability
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (customer_id) REFERENCES public.customer_requests(customer_id) ON DELETE SET NULL;


--
-- Name: stylist_availability [redacted-token]; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stylist_availability
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (stylist_id) REFERENCES public.stylists(id) ON DELETE CASCADE;


--
-- Name: stylists stylists_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stylists
    ADD CONSTRAINT stylists_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(org_id);


--
-- Name: objects objects_bucketId_fkey; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.objects
    ADD CONSTRAINT "objects_bucketId_fkey" FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: s3_multipart_uploads [redacted-token]; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.s3_multipart_uploads
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: [redacted-token] [redacted-token]; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.[redacted-token]
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (bucket_id) REFERENCES storage.buckets(id);


--
-- Name: [redacted-token] [redacted-token]; Type: FK CONSTRAINT; Schema: storage; Owner: -
--

ALTER TABLE ONLY storage.[redacted-token]
    ADD CONSTRAINT [redacted-token] FOREIGN KEY (upload_id) REFERENCES storage.s3_multipart_uploads(id) ON DELETE CASCADE;


--
-- Name: audit_log_entries; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.audit_log_entries ENABLE ROW LEVEL SECURITY;

--
-- Name: flow_state; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.flow_state ENABLE ROW LEVEL SECURITY;

--
-- Name: identities; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.identities ENABLE ROW LEVEL SECURITY;

--
-- Name: instances; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.instances ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_amr_claims; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_amr_claims ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_challenges; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_challenges ENABLE ROW LEVEL SECURITY;

--
-- Name: mfa_factors; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.mfa_factors ENABLE ROW LEVEL SECURITY;

--
-- Name: one_time_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.one_time_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: refresh_tokens; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.refresh_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.saml_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: saml_relay_states; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.saml_relay_states ENABLE ROW LEVEL SECURITY;

--
-- Name: schema_migrations; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.schema_migrations ENABLE ROW LEVEL SECURITY;

--
-- Name: sessions; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_domains; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sso_domains ENABLE ROW LEVEL SECURITY;

--
-- Name: sso_providers; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.sso_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: users; Type: ROW SECURITY; Schema: auth; Owner: -
--

ALTER TABLE auth.users ENABLE ROW LEVEL SECURITY;

--
-- Name: messages; Type: ROW SECURITY; Schema: realtime; Owner: -
--

ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;

--
-- Name: buckets; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;

--
-- Name: migrations; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.migrations ENABLE ROW LEVEL SECURITY;

--
-- Name: objects; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;

--
-- Name: s3_multipart_uploads; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.s3_multipart_uploads ENABLE ROW LEVEL SECURITY;

--
-- Name: [redacted-token]; Type: ROW SECURITY; Schema: storage; Owner: -
--

ALTER TABLE storage.[redacted-token] ENABLE ROW LEVEL SECURITY;

--
-- Name: supabase_realtime; Type: PUBLICATION; Schema: -; Owner: -
--

CREATE PUBLICATION supabase_realtime WITH (publish = 'insert, update, delete, truncate');


--
-- Name: SCHEMA auth; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA auth TO anon;
GRANT USAGE ON SCHEMA auth TO authenticated;
GRANT USAGE ON SCHEMA auth TO service_role;
GRANT ALL ON SCHEMA auth TO supabase_auth_admin;
GRANT ALL ON SCHEMA auth TO dashboard_user;
GRANT USAGE ON SCHEMA auth TO postgres;


--
-- Name: SCHEMA extensions; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA extensions TO anon;
GRANT USAGE ON SCHEMA extensions TO authenticated;
GRANT USAGE ON SCHEMA extensions TO service_role;
GRANT ALL ON SCHEMA extensions TO dashboard_user;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA public TO postgres;
GRANT USAGE ON SCHEMA public TO anon;
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT USAGE ON SCHEMA public TO service_role;


--
-- Name: SCHEMA realtime; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA realtime TO postgres;
GRANT USAGE ON SCHEMA realtime TO anon;
GRANT USAGE ON SCHEMA realtime TO authenticated;
GRANT USAGE ON SCHEMA realtime TO service_role;
GRANT ALL ON SCHEMA realtime TO supabase_realtime_admin;


--
-- Name: SCHEMA storage; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA storage TO postgres WITH GRANT OPTION;
GRANT USAGE ON SCHEMA storage TO anon;
GRANT USAGE ON SCHEMA storage TO authenticated;
GRANT USAGE ON SCHEMA storage TO service_role;
GRANT ALL ON SCHEMA storage TO supabase_storage_admin;
GRANT ALL ON SCHEMA storage TO dashboard_user;


--
-- Name: SCHEMA vault; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA vault TO postgres WITH GRANT OPTION;
GRANT USAGE ON SCHEMA vault TO service_role;


--
-- Name: FUNCTION citextin(cstring); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citextin(cstring) TO postgres;
GRANT ALL ON FUNCTION public.citextin(cstring) TO anon;
GRANT ALL ON FUNCTION public.citextin(cstring) TO authenticated;
GRANT ALL ON FUNCTION public.citextin(cstring) TO service_role;


--
-- Name: FUNCTION citextout(public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citextout(public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citextout(public.citext) TO anon;
GRANT ALL ON FUNCTION public.citextout(public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citextout(public.citext) TO service_role;


--
-- Name: FUNCTION citextrecv(internal); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citextrecv(internal) TO postgres;
GRANT ALL ON FUNCTION public.citextrecv(internal) TO anon;
GRANT ALL ON FUNCTION public.citextrecv(internal) TO authenticated;
GRANT ALL ON FUNCTION public.citextrecv(internal) TO service_role;


--
-- Name: FUNCTION citextsend(public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citextsend(public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citextsend(public.citext) TO anon;
GRANT ALL ON FUNCTION public.citextsend(public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citextsend(public.citext) TO service_role;


--
-- Name: FUNCTION citext(boolean); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext(boolean) TO postgres;
GRANT ALL ON FUNCTION public.citext(boolean) TO anon;
GRANT ALL ON FUNCTION public.citext(boolean) TO authenticated;
GRANT ALL ON FUNCTION public.citext(boolean) TO service_role;


--
-- Name: FUNCTION citext(character); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext(character) TO postgres;
GRANT ALL ON FUNCTION public.citext(character) TO anon;
GRANT ALL ON FUNCTION public.citext(character) TO authenticated;
GRANT ALL ON FUNCTION public.citext(character) TO service_role;


--
-- Name: FUNCTION citext(inet); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext(inet) TO postgres;
GRANT ALL ON FUNCTION public.citext(inet) TO anon;
GRANT ALL ON FUNCTION public.citext(inet) TO authenticated;
GRANT ALL ON FUNCTION public.citext(inet) TO service_role;


--
-- Name: FUNCTION email(); Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON FUNCTION auth.email() TO dashboard_user;


--
-- Name: FUNCTION jwt(); Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON FUNCTION auth.jwt() TO postgres;
GRANT ALL ON FUNCTION auth.jwt() TO dashboard_user;


--
-- Name: FUNCTION role(); Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON FUNCTION auth.role() TO dashboard_user;


--
-- Name: FUNCTION uid(); Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON FUNCTION auth.uid() TO dashboard_user;


--
-- Name: FUNCTION armor(bytea); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.armor(bytea) FROM postgres;
GRANT ALL ON FUNCTION extensions.armor(bytea) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.armor(bytea) TO dashboard_user;


--
-- Name: FUNCTION armor(bytea, text[], text[]); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.armor(bytea, text[], text[]) FROM postgres;
GRANT ALL ON FUNCTION extensions.armor(bytea, text[], text[]) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.armor(bytea, text[], text[]) TO dashboard_user;


--
-- Name: FUNCTION crypt(text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.crypt(text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.crypt(text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.crypt(text, text) TO dashboard_user;


--
-- Name: FUNCTION dearmor(text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.dearmor(text) FROM postgres;
GRANT ALL ON FUNCTION extensions.dearmor(text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.dearmor(text) TO dashboard_user;


--
-- Name: FUNCTION decrypt(bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.decrypt(bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.decrypt(bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.decrypt(bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION decrypt_iv(bytea, bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.decrypt_iv(bytea, bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.decrypt_iv(bytea, bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.decrypt_iv(bytea, bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION digest(bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.digest(bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.digest(bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.digest(bytea, text) TO dashboard_user;


--
-- Name: FUNCTION digest(text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.digest(text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.digest(text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.digest(text, text) TO dashboard_user;


--
-- Name: FUNCTION encrypt(bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.encrypt(bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.encrypt(bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.encrypt(bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION encrypt_iv(bytea, bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.encrypt_iv(bytea, bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.encrypt_iv(bytea, bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.encrypt_iv(bytea, bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION gen_random_bytes(integer); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.gen_random_bytes(integer) FROM postgres;
GRANT ALL ON FUNCTION extensions.gen_random_bytes(integer) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.gen_random_bytes(integer) TO dashboard_user;


--
-- Name: FUNCTION gen_random_uuid(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.gen_random_uuid() FROM postgres;
GRANT ALL ON FUNCTION extensions.gen_random_uuid() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.gen_random_uuid() TO dashboard_user;


--
-- Name: FUNCTION gen_salt(text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.gen_salt(text) FROM postgres;
GRANT ALL ON FUNCTION extensions.gen_salt(text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.gen_salt(text) TO dashboard_user;


--
-- Name: FUNCTION gen_salt(text, integer); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.gen_salt(text, integer) FROM postgres;
GRANT ALL ON FUNCTION extensions.gen_salt(text, integer) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.gen_salt(text, integer) TO dashboard_user;


--
-- Name: FUNCTION grant_pg_cron_access(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.grant_pg_cron_access() FROM supabase_admin;
GRANT ALL ON FUNCTION extensions.grant_pg_cron_access() TO supabase_admin WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.grant_pg_cron_access() TO dashboard_user;


--
-- Name: FUNCTION grant_pg_graphql_access(); Type: ACL; Schema: extensions; Owner: -
--

GRANT ALL ON FUNCTION extensions.grant_pg_graphql_access() TO postgres WITH GRANT OPTION;


--
-- Name: FUNCTION grant_pg_net_access(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.grant_pg_net_access() FROM supabase_admin;
GRANT ALL ON FUNCTION extensions.grant_pg_net_access() TO supabase_admin WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.grant_pg_net_access() TO dashboard_user;


--
-- Name: FUNCTION hmac(bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.hmac(bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.hmac(bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.hmac(bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION hmac(text, text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.hmac(text, text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.hmac(text, text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.hmac(text, text, text) TO dashboard_user;


--
-- Name: FUNCTION pg_stat_statements(showtext boolean, OUT userid oid, OUT dbid oid, OUT toplevel boolean, OUT queryid bigint, OUT query text, OUT plans bigint, OUT total_plan_time double precision, OUT min_plan_time double precision, OUT max_plan_time double precision, OUT mean_plan_time double precision, OUT stddev_plan_time double precision, OUT calls bigint, OUT total_exec_time double precision, OUT min_exec_time double precision, OUT max_exec_time double precision, OUT mean_exec_time double precision, OUT stddev_exec_time double precision, OUT rows bigint, OUT shared_blks_hit bigint, OUT shared_blks_read bigint, OUT shared_blks_dirtied bigint, OUT shared_blks_written bigint, OUT local_blks_hit bigint, OUT local_blks_read bigint, OUT local_blks_dirtied bigint, OUT local_blks_written bigint, OUT temp_blks_read bigint, OUT temp_blks_written bigint, OUT shared_blk_read_time double precision, OUT shared_blk_write_time double precision, OUT local_blk_read_time double precision, OUT local_blk_write_time double precision, OUT temp_blk_read_time double precision, OUT temp_blk_write_time double precision, OUT wal_records bigint, OUT wal_fpi bigint, OUT wal_bytes numeric, OUT jit_functions bigint, OUT jit_generation_time double precision, OUT jit_inlining_count bigint, OUT jit_inlining_time double precision, OUT jit_optimization_count bigint, OUT jit_optimization_time double precision, OUT jit_emission_count bigint, OUT jit_emission_time double precision, OUT jit_deform_count bigint, OUT jit_deform_time double precision, OUT stats_since timestamp with time zone, OUT minmax_stats_since timestamp with time zone); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pg_stat_statements(showtext boolean, OUT userid oid, OUT dbid oid, OUT toplevel boolean, OUT queryid bigint, OUT query text, OUT plans bigint, OUT total_plan_time double precision, OUT min_plan_time double precision, OUT max_plan_time double precision, OUT mean_plan_time double precision, OUT stddev_plan_time double precision, OUT calls bigint, OUT total_exec_time double precision, OUT min_exec_time double precision, OUT max_exec_time double precision, OUT mean_exec_time double precision, OUT stddev_exec_time double precision, OUT rows bigint, OUT shared_blks_hit bigint, OUT shared_blks_read bigint, OUT shared_blks_dirtied bigint, OUT shared_blks_written bigint, OUT local_blks_hit bigint, OUT local_blks_read bigint, OUT local_blks_dirtied bigint, OUT local_blks_written bigint, OUT temp_blks_read bigint, OUT temp_blks_written bigint, OUT shared_blk_read_time double precision, OUT shared_blk_write_time double precision, OUT local_blk_read_time double precision, OUT local_blk_write_time double precision, OUT temp_blk_read_time double precision, OUT temp_blk_write_time double precision, OUT wal_records bigint, OUT wal_fpi bigint, OUT wal_bytes numeric, OUT jit_functions bigint, OUT jit_generation_time double precision, OUT jit_inlining_count bigint, OUT jit_inlining_time double precision, OUT jit_optimization_count bigint, OUT jit_optimization_time double precision, OUT jit_emission_count bigint, OUT jit_emission_time double precision, OUT jit_deform_count bigint, OUT jit_deform_time double precision, OUT stats_since timestamp with time zone, OUT minmax_stats_since timestamp with time zone) FROM postgres;
GRANT ALL ON FUNCTION extensions.pg_stat_statements(showtext boolean, OUT userid oid, OUT dbid oid, OUT toplevel boolean, OUT queryid bigint, OUT query text, OUT plans bigint, OUT total_plan_time double precision, OUT min_plan_time double precision, OUT max_plan_time double precision, OUT mean_plan_time double precision, OUT stddev_plan_time double precision, OUT calls bigint, OUT total_exec_time double precision, OUT min_exec_time double precision, OUT max_exec_time double precision, OUT mean_exec_time double precision, OUT stddev_exec_time double precision, OUT rows bigint, OUT shared_blks_hit bigint, OUT shared_blks_read bigint, OUT shared_blks_dirtied bigint, OUT shared_blks_written bigint, OUT local_blks_hit bigint, OUT local_blks_read bigint, OUT local_blks_dirtied bigint, OUT local_blks_written bigint, OUT temp_blks_read bigint, OUT temp_blks_written bigint, OUT shared_blk_read_time double precision, OUT shared_blk_write_time double precision, OUT local_blk_read_time double precision, OUT local_blk_write_time double precision, OUT temp_blk_read_time double precision, OUT temp_blk_write_time double precision, OUT wal_records bigint, OUT wal_fpi bigint, OUT wal_bytes numeric, OUT jit_functions bigint, OUT jit_generation_time double precision, OUT jit_inlining_count bigint, OUT jit_inlining_time double precision, OUT jit_optimization_count bigint, OUT jit_optimization_time double precision, OUT jit_emission_count bigint, OUT jit_emission_time double precision, OUT jit_deform_count bigint, OUT jit_deform_time double precision, OUT stats_since timestamp with time zone, OUT minmax_stats_since timestamp with time zone) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pg_stat_statements(showtext boolean, OUT userid oid, OUT dbid oid, OUT toplevel boolean, OUT queryid bigint, OUT query text, OUT plans bigint, OUT total_plan_time double precision, OUT min_plan_time double precision, OUT max_plan_time double precision, OUT mean_plan_time double precision, OUT stddev_plan_time double precision, OUT calls bigint, OUT total_exec_time double precision, OUT min_exec_time double precision, OUT max_exec_time double precision, OUT mean_exec_time double precision, OUT stddev_exec_time double precision, OUT rows bigint, OUT shared_blks_hit bigint, OUT shared_blks_read bigint, OUT shared_blks_dirtied bigint, OUT shared_blks_written bigint, OUT local_blks_hit bigint, OUT local_blks_read bigint, OUT local_blks_dirtied bigint, OUT local_blks_written bigint, OUT temp_blks_read bigint, OUT temp_blks_written bigint, OUT shared_blk_read_time double precision, OUT shared_blk_write_time double precision, OUT local_blk_read_time double precision, OUT local_blk_write_time double precision, OUT temp_blk_read_time double precision, OUT temp_blk_write_time double precision, OUT wal_records bigint, OUT wal_fpi bigint, OUT wal_bytes numeric, OUT jit_functions bigint, OUT jit_generation_time double precision, OUT jit_inlining_count bigint, OUT jit_inlining_time double precision, OUT jit_optimization_count bigint, OUT jit_optimization_time double precision, OUT jit_emission_count bigint, OUT jit_emission_time double precision, OUT jit_deform_count bigint, OUT jit_deform_time double precision, OUT stats_since timestamp with time zone, OUT minmax_stats_since timestamp with time zone) TO dashboard_user;


--
-- Name: FUNCTION pg_stat_statements_info(OUT dealloc bigint, OUT stats_reset timestamp with time zone); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pg_stat_statements_info(OUT dealloc bigint, OUT stats_reset timestamp with time zone) FROM postgres;
GRANT ALL ON FUNCTION extensions.pg_stat_statements_info(OUT dealloc bigint, OUT stats_reset timestamp with time zone) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pg_stat_statements_info(OUT dealloc bigint, OUT stats_reset timestamp with time zone) TO dashboard_user;


--
-- Name: FUNCTION [redacted-token](userid oid, dbid oid, queryid bigint, minmax_only boolean); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.[redacted-token](userid oid, dbid oid, queryid bigint, minmax_only boolean) FROM postgres;
GRANT ALL ON FUNCTION extensions.[redacted-token](userid oid, dbid oid, queryid bigint, minmax_only boolean) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.[redacted-token](userid oid, dbid oid, queryid bigint, minmax_only boolean) TO dashboard_user;


--
-- Name: FUNCTION pgp_armor_headers(text, OUT key text, OUT value text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_armor_headers(text, OUT key text, OUT value text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_armor_headers(text, OUT key text, OUT value text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_armor_headers(text, OUT key text, OUT value text) TO dashboard_user;


--
-- Name: FUNCTION pgp_key_id(bytea); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_key_id(bytea) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_key_id(bytea) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_key_id(bytea) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_decrypt(bytea, bytea); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_decrypt(bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_decrypt(bytea, bytea, text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea, text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea, text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt(bytea, bytea, text, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_decrypt_bytea(bytea, bytea); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_decrypt_bytea(bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_decrypt_bytea(bytea, bytea, text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea, text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea, text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_decrypt_bytea(bytea, bytea, text, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_encrypt(text, bytea); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_encrypt(text, bytea) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt(text, bytea) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt(text, bytea) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_encrypt(text, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_encrypt(text, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt(text, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt(text, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_encrypt_bytea(bytea, bytea); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_encrypt_bytea(bytea, bytea) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt_bytea(bytea, bytea) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt_bytea(bytea, bytea) TO dashboard_user;


--
-- Name: FUNCTION pgp_pub_encrypt_bytea(bytea, bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_pub_encrypt_bytea(bytea, bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt_bytea(bytea, bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_pub_encrypt_bytea(bytea, bytea, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_decrypt(bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_decrypt(bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt(bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt(bytea, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_decrypt(bytea, text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_decrypt(bytea, text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt(bytea, text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt(bytea, text, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_decrypt_bytea(bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_decrypt_bytea(bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt_bytea(bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt_bytea(bytea, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_decrypt_bytea(bytea, text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_decrypt_bytea(bytea, text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt_bytea(bytea, text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_decrypt_bytea(bytea, text, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_encrypt(text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_encrypt(text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt(text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt(text, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_encrypt(text, text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_encrypt(text, text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt(text, text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt(text, text, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_encrypt_bytea(bytea, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_encrypt_bytea(bytea, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt_bytea(bytea, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt_bytea(bytea, text) TO dashboard_user;


--
-- Name: FUNCTION pgp_sym_encrypt_bytea(bytea, text, text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.pgp_sym_encrypt_bytea(bytea, text, text) FROM postgres;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt_bytea(bytea, text, text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.pgp_sym_encrypt_bytea(bytea, text, text) TO dashboard_user;


--
-- Name: FUNCTION pgrst_ddl_watch(); Type: ACL; Schema: extensions; Owner: -
--

GRANT ALL ON FUNCTION extensions.pgrst_ddl_watch() TO postgres WITH GRANT OPTION;


--
-- Name: FUNCTION pgrst_drop_watch(); Type: ACL; Schema: extensions; Owner: -
--

GRANT ALL ON FUNCTION extensions.pgrst_drop_watch() TO postgres WITH GRANT OPTION;


--
-- Name: FUNCTION set_graphql_placeholder(); Type: ACL; Schema: extensions; Owner: -
--

GRANT ALL ON FUNCTION extensions.set_graphql_placeholder() TO postgres WITH GRANT OPTION;


--
-- Name: FUNCTION uuid_generate_v1(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_generate_v1() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_generate_v1() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_generate_v1() TO dashboard_user;


--
-- Name: FUNCTION uuid_generate_v1mc(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_generate_v1mc() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_generate_v1mc() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_generate_v1mc() TO dashboard_user;


--
-- Name: FUNCTION uuid_generate_v3(namespace uuid, name text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_generate_v3(namespace uuid, name text) FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_generate_v3(namespace uuid, name text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_generate_v3(namespace uuid, name text) TO dashboard_user;


--
-- Name: FUNCTION uuid_generate_v4(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_generate_v4() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_generate_v4() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_generate_v4() TO dashboard_user;


--
-- Name: FUNCTION uuid_generate_v5(namespace uuid, name text); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_generate_v5(namespace uuid, name text) FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_generate_v5(namespace uuid, name text) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_generate_v5(namespace uuid, name text) TO dashboard_user;


--
-- Name: FUNCTION uuid_nil(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_nil() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_nil() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_nil() TO dashboard_user;


--
-- Name: FUNCTION uuid_ns_dns(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_ns_dns() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_ns_dns() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_ns_dns() TO dashboard_user;


--
-- Name: FUNCTION uuid_ns_oid(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_ns_oid() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_ns_oid() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_ns_oid() TO dashboard_user;


--
-- Name: FUNCTION uuid_ns_url(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_ns_url() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_ns_url() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_ns_url() TO dashboard_user;


--
-- Name: FUNCTION uuid_ns_x500(); Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON FUNCTION extensions.uuid_ns_x500() FROM postgres;
GRANT ALL ON FUNCTION extensions.uuid_ns_x500() TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION extensions.uuid_ns_x500() TO dashboard_user;


--
-- Name: FUNCTION graphql("operationName" text, query text, variables jsonb, extensions jsonb); Type: ACL; Schema: graphql_public; Owner: -
--

GRANT ALL ON FUNCTION graphql_public.graphql("operationName" text, query text, variables jsonb, extensions jsonb) TO postgres;
GRANT ALL ON FUNCTION graphql_public.graphql("operationName" text, query text, variables jsonb, extensions jsonb) TO anon;
GRANT ALL ON FUNCTION graphql_public.graphql("operationName" text, query text, variables jsonb, extensions jsonb) TO authenticated;
GRANT ALL ON FUNCTION graphql_public.graphql("operationName" text, query text, variables jsonb, extensions jsonb) TO service_role;


--
-- Name: FUNCTION get_auth(p_usename text); Type: ACL; Schema: pgbouncer; Owner: -
--

REVOKE ALL ON FUNCTION pgbouncer.get_auth(p_usename text) FROM PUBLIC;
GRANT ALL ON FUNCTION pgbouncer.get_auth(p_usename text) TO pgbouncer;
GRANT ALL ON FUNCTION pgbouncer.get_auth(p_usename text) TO postgres;


--
-- Name: FUNCTION citext_cmp(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_cmp(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_cmp(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_cmp(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_cmp(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_eq(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_eq(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_eq(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_eq(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_eq(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_ge(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_ge(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_ge(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_ge(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_ge(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_gt(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_gt(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_gt(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_gt(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_gt(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_hash(public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_hash(public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_hash(public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_hash(public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_hash(public.citext) TO service_role;


--
-- Name: FUNCTION citext_hash_extended(public.citext, bigint); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_hash_extended(public.citext, bigint) TO postgres;
GRANT ALL ON FUNCTION public.citext_hash_extended(public.citext, bigint) TO anon;
GRANT ALL ON FUNCTION public.citext_hash_extended(public.citext, bigint) TO authenticated;
GRANT ALL ON FUNCTION public.citext_hash_extended(public.citext, bigint) TO service_role;


--
-- Name: FUNCTION citext_larger(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_larger(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_larger(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_larger(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_larger(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_le(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_le(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_le(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_le(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_le(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_lt(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_lt(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_lt(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_lt(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_lt(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_ne(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_ne(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_ne(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_ne(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_ne(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_pattern_cmp(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_pattern_cmp(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_pattern_cmp(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_pattern_cmp(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_pattern_cmp(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_pattern_ge(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_pattern_ge(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_pattern_ge(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_pattern_ge(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_pattern_ge(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_pattern_gt(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_pattern_gt(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_pattern_gt(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_pattern_gt(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_pattern_gt(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_pattern_le(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_pattern_le(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_pattern_le(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_pattern_le(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_pattern_le(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_pattern_lt(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_pattern_lt(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_pattern_lt(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_pattern_lt(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_pattern_lt(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION citext_smaller(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.citext_smaller(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.citext_smaller(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.citext_smaller(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.citext_smaller(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION [redacted-token](); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.[redacted-token]() TO anon;
GRANT ALL ON FUNCTION public.[redacted-token]() TO authenticated;
GRANT ALL ON FUNCTION public.[redacted-token]() TO service_role;


--
-- Name: FUNCTION [redacted-token](); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.[redacted-token]() TO anon;
GRANT ALL ON FUNCTION public.[redacted-token]() TO authenticated;
GRANT ALL ON FUNCTION public.[redacted-token]() TO service_role;


--
-- Name: FUNCTION regexp_match(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION regexp_match(public.citext, public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_match(public.citext, public.citext, text) TO service_role;


--
-- Name: FUNCTION regexp_matches(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION regexp_matches(public.citext, public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_matches(public.citext, public.citext, text) TO service_role;


--
-- Name: FUNCTION regexp_replace(public.citext, public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text) TO service_role;


--
-- Name: FUNCTION regexp_replace(public.citext, public.citext, text, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text, text) TO postgres;
GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text, text) TO anon;
GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text, text) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_replace(public.citext, public.citext, text, text) TO service_role;


--
-- Name: FUNCTION regexp_split_to_array(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION regexp_split_to_array(public.citext, public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_split_to_array(public.citext, public.citext, text) TO service_role;


--
-- Name: FUNCTION regexp_split_to_table(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION regexp_split_to_table(public.citext, public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.regexp_split_to_table(public.citext, public.citext, text) TO service_role;


--
-- Name: FUNCTION replace(public.citext, public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.replace(public.citext, public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.replace(public.citext, public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.replace(public.citext, public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.replace(public.citext, public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION [redacted-token](); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.[redacted-token]() TO anon;
GRANT ALL ON FUNCTION public.[redacted-token]() TO authenticated;
GRANT ALL ON FUNCTION public.[redacted-token]() TO service_role;


--
-- Name: FUNCTION split_part(public.citext, public.citext, integer); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.split_part(public.citext, public.citext, integer) TO postgres;
GRANT ALL ON FUNCTION public.split_part(public.citext, public.citext, integer) TO anon;
GRANT ALL ON FUNCTION public.split_part(public.citext, public.citext, integer) TO authenticated;
GRANT ALL ON FUNCTION public.split_part(public.citext, public.citext, integer) TO service_role;


--
-- Name: FUNCTION strpos(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.strpos(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.strpos(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.strpos(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.strpos(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION texticlike(public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticlike(public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.texticlike(public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.texticlike(public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.texticlike(public.citext, text) TO service_role;


--
-- Name: FUNCTION texticlike(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticlike(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.texticlike(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.texticlike(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.texticlike(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION texticnlike(public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticnlike(public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.texticnlike(public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.texticnlike(public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.texticnlike(public.citext, text) TO service_role;


--
-- Name: FUNCTION texticnlike(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticnlike(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.texticnlike(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.texticnlike(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.texticnlike(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION texticregexeq(public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticregexeq(public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.texticregexeq(public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.texticregexeq(public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.texticregexeq(public.citext, text) TO service_role;


--
-- Name: FUNCTION texticregexeq(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticregexeq(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.texticregexeq(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.texticregexeq(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.texticregexeq(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION texticregexne(public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticregexne(public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.texticregexne(public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.texticregexne(public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.texticregexne(public.citext, text) TO service_role;


--
-- Name: FUNCTION texticregexne(public.citext, public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.texticregexne(public.citext, public.citext) TO postgres;
GRANT ALL ON FUNCTION public.texticregexne(public.citext, public.citext) TO anon;
GRANT ALL ON FUNCTION public.texticregexne(public.citext, public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.texticregexne(public.citext, public.citext) TO service_role;


--
-- Name: FUNCTION translate(public.citext, public.citext, text); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.translate(public.citext, public.citext, text) TO postgres;
GRANT ALL ON FUNCTION public.translate(public.citext, public.citext, text) TO anon;
GRANT ALL ON FUNCTION public.translate(public.citext, public.citext, text) TO authenticated;
GRANT ALL ON FUNCTION public.translate(public.citext, public.citext, text) TO service_role;


--
-- Name: FUNCTION [redacted-token](); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.[redacted-token]() TO anon;
GRANT ALL ON FUNCTION public.[redacted-token]() TO authenticated;
GRANT ALL ON FUNCTION public.[redacted-token]() TO service_role;


--
-- Name: FUNCTION apply_rls(wal jsonb, max_record_bytes integer); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer) TO postgres;
GRANT ALL ON FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer) TO dashboard_user;
GRANT ALL ON FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer) TO anon;
GRANT ALL ON FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer) TO authenticated;
GRANT ALL ON FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer) TO service_role;
GRANT ALL ON FUNCTION realtime.apply_rls(wal jsonb, max_record_bytes integer) TO supabase_realtime_admin;


--
-- Name: FUNCTION broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text) TO postgres;
GRANT ALL ON FUNCTION realtime.broadcast_changes(topic_name text, event_name text, operation text, table_name text, table_schema text, new record, old record, level text) TO dashboard_user;


--
-- Name: FUNCTION [redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.[redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]) TO postgres;
GRANT ALL ON FUNCTION realtime.[redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]) TO dashboard_user;
GRANT ALL ON FUNCTION realtime.[redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]) TO anon;
GRANT ALL ON FUNCTION realtime.[redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]) TO authenticated;
GRANT ALL ON FUNCTION realtime.[redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]) TO service_role;
GRANT ALL ON FUNCTION realtime.[redacted-token](prepared_statement_name text, entity regclass, columns realtime.wal_column[]) TO supabase_realtime_admin;


--
-- Name: FUNCTION "cast"(val text, type_ regtype); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime."cast"(val text, type_ regtype) TO postgres;
GRANT ALL ON FUNCTION realtime."cast"(val text, type_ regtype) TO dashboard_user;
GRANT ALL ON FUNCTION realtime."cast"(val text, type_ regtype) TO anon;
GRANT ALL ON FUNCTION realtime."cast"(val text, type_ regtype) TO authenticated;
GRANT ALL ON FUNCTION realtime."cast"(val text, type_ regtype) TO service_role;
GRANT ALL ON FUNCTION realtime."cast"(val text, type_ regtype) TO supabase_realtime_admin;


--
-- Name: FUNCTION check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) TO postgres;
GRANT ALL ON FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) TO dashboard_user;
GRANT ALL ON FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) TO anon;
GRANT ALL ON FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) TO authenticated;
GRANT ALL ON FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) TO service_role;
GRANT ALL ON FUNCTION realtime.check_equality_op(op realtime.equality_op, type_ regtype, val_1 text, val_2 text) TO supabase_realtime_admin;


--
-- Name: FUNCTION [redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.[redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]) TO postgres;
GRANT ALL ON FUNCTION realtime.[redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]) TO dashboard_user;
GRANT ALL ON FUNCTION realtime.[redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]) TO anon;
GRANT ALL ON FUNCTION realtime.[redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]) TO authenticated;
GRANT ALL ON FUNCTION realtime.[redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]) TO service_role;
GRANT ALL ON FUNCTION realtime.[redacted-token](columns realtime.wal_column[], filters realtime.user_defined_filter[]) TO supabase_realtime_admin;


--
-- Name: FUNCTION list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) TO postgres;
GRANT ALL ON FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) TO dashboard_user;
GRANT ALL ON FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) TO anon;
GRANT ALL ON FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) TO authenticated;
GRANT ALL ON FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) TO service_role;
GRANT ALL ON FUNCTION realtime.list_changes(publication name, slot_name name, max_changes integer, max_record_bytes integer) TO supabase_realtime_admin;


--
-- Name: FUNCTION quote_wal2json(entity regclass); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.quote_wal2json(entity regclass) TO postgres;
GRANT ALL ON FUNCTION realtime.quote_wal2json(entity regclass) TO dashboard_user;
GRANT ALL ON FUNCTION realtime.quote_wal2json(entity regclass) TO anon;
GRANT ALL ON FUNCTION realtime.quote_wal2json(entity regclass) TO authenticated;
GRANT ALL ON FUNCTION realtime.quote_wal2json(entity regclass) TO service_role;
GRANT ALL ON FUNCTION realtime.quote_wal2json(entity regclass) TO supabase_realtime_admin;


--
-- Name: FUNCTION send(payload jsonb, event text, topic text, private boolean); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.send(payload jsonb, event text, topic text, private boolean) TO postgres;
GRANT ALL ON FUNCTION realtime.send(payload jsonb, event text, topic text, private boolean) TO dashboard_user;


--
-- Name: FUNCTION [redacted-token](); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.[redacted-token]() TO postgres;
GRANT ALL ON FUNCTION realtime.[redacted-token]() TO dashboard_user;
GRANT ALL ON FUNCTION realtime.[redacted-token]() TO anon;
GRANT ALL ON FUNCTION realtime.[redacted-token]() TO authenticated;
GRANT ALL ON FUNCTION realtime.[redacted-token]() TO service_role;
GRANT ALL ON FUNCTION realtime.[redacted-token]() TO supabase_realtime_admin;


--
-- Name: FUNCTION to_regrole(role_name text); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.to_regrole(role_name text) TO postgres;
GRANT ALL ON FUNCTION realtime.to_regrole(role_name text) TO dashboard_user;
GRANT ALL ON FUNCTION realtime.to_regrole(role_name text) TO anon;
GRANT ALL ON FUNCTION realtime.to_regrole(role_name text) TO authenticated;
GRANT ALL ON FUNCTION realtime.to_regrole(role_name text) TO service_role;
GRANT ALL ON FUNCTION realtime.to_regrole(role_name text) TO supabase_realtime_admin;


--
-- Name: FUNCTION topic(); Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON FUNCTION realtime.topic() TO postgres;
GRANT ALL ON FUNCTION realtime.topic() TO dashboard_user;


--
-- Name: FUNCTION [redacted-token](message bytea, additional bytea, key_id bigint, context bytea, nonce bytea); Type: ACL; Schema: vault; Owner: -
--

GRANT ALL ON FUNCTION vault.[redacted-token](message bytea, additional bytea, key_id bigint, context bytea, nonce bytea) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION vault.[redacted-token](message bytea, additional bytea, key_id bigint, context bytea, nonce bytea) TO service_role;


--
-- Name: FUNCTION create_secret(new_secret text, new_name text, new_description text, new_key_id uuid); Type: ACL; Schema: vault; Owner: -
--

GRANT ALL ON FUNCTION vault.create_secret(new_secret text, new_name text, new_description text, new_key_id uuid) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION vault.create_secret(new_secret text, new_name text, new_description text, new_key_id uuid) TO service_role;


--
-- Name: FUNCTION update_secret(secret_id uuid, new_secret text, new_name text, new_description text, new_key_id uuid); Type: ACL; Schema: vault; Owner: -
--

GRANT ALL ON FUNCTION vault.update_secret(secret_id uuid, new_secret text, new_name text, new_description text, new_key_id uuid) TO postgres WITH GRANT OPTION;
GRANT ALL ON FUNCTION vault.update_secret(secret_id uuid, new_secret text, new_name text, new_description text, new_key_id uuid) TO service_role;


--
-- Name: FUNCTION max(public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.max(public.citext) TO postgres;
GRANT ALL ON FUNCTION public.max(public.citext) TO anon;
GRANT ALL ON FUNCTION public.max(public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.max(public.citext) TO service_role;


--
-- Name: FUNCTION min(public.citext); Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON FUNCTION public.min(public.citext) TO postgres;
GRANT ALL ON FUNCTION public.min(public.citext) TO anon;
GRANT ALL ON FUNCTION public.min(public.citext) TO authenticated;
GRANT ALL ON FUNCTION public.min(public.citext) TO service_role;


--
-- Name: TABLE audit_log_entries; Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON TABLE auth.audit_log_entries TO dashboard_user;
GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.audit_log_entries TO postgres;
GRANT SELECT ON TABLE auth.audit_log_entries TO postgres WITH GRANT OPTION;


--
-- Name: TABLE flow_state; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.flow_state TO postgres;
GRANT SELECT ON TABLE auth.flow_state TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.flow_state TO dashboard_user;


--
-- Name: TABLE identities; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.identities TO postgres;
GRANT SELECT ON TABLE auth.identities TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.identities TO dashboard_user;


--
-- Name: TABLE instances; Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON TABLE auth.instances TO dashboard_user;
GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.instances TO postgres;
GRANT SELECT ON TABLE auth.instances TO postgres WITH GRANT OPTION;


--
-- Name: TABLE mfa_amr_claims; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.mfa_amr_claims TO postgres;
GRANT SELECT ON TABLE auth.mfa_amr_claims TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.mfa_amr_claims TO dashboard_user;


--
-- Name: TABLE mfa_challenges; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.mfa_challenges TO postgres;
GRANT SELECT ON TABLE auth.mfa_challenges TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.mfa_challenges TO dashboard_user;


--
-- Name: TABLE mfa_factors; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.mfa_factors TO postgres;
GRANT SELECT ON TABLE auth.mfa_factors TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.mfa_factors TO dashboard_user;


--
-- Name: TABLE oauth_clients; Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON TABLE auth.oauth_clients TO postgres;
GRANT ALL ON TABLE auth.oauth_clients TO dashboard_user;


--
-- Name: TABLE one_time_tokens; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.one_time_tokens TO postgres;
GRANT SELECT ON TABLE auth.one_time_tokens TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.one_time_tokens TO dashboard_user;


--
-- Name: TABLE refresh_tokens; Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON TABLE auth.refresh_tokens TO dashboard_user;
GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.refresh_tokens TO postgres;
GRANT SELECT ON TABLE auth.refresh_tokens TO postgres WITH GRANT OPTION;


--
-- Name: SEQUENCE refresh_tokens_id_seq; Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON SEQUENCE auth.refresh_tokens_id_seq TO dashboard_user;
GRANT ALL ON SEQUENCE auth.refresh_tokens_id_seq TO postgres;


--
-- Name: TABLE saml_providers; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.saml_providers TO postgres;
GRANT SELECT ON TABLE auth.saml_providers TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.saml_providers TO dashboard_user;


--
-- Name: TABLE saml_relay_states; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.saml_relay_states TO postgres;
GRANT SELECT ON TABLE auth.saml_relay_states TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.saml_relay_states TO dashboard_user;


--
-- Name: TABLE sessions; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.sessions TO postgres;
GRANT SELECT ON TABLE auth.sessions TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.sessions TO dashboard_user;


--
-- Name: TABLE sso_domains; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.sso_domains TO postgres;
GRANT SELECT ON TABLE auth.sso_domains TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.sso_domains TO dashboard_user;


--
-- Name: TABLE sso_providers; Type: ACL; Schema: auth; Owner: -
--

GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.sso_providers TO postgres;
GRANT SELECT ON TABLE auth.sso_providers TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE auth.sso_providers TO dashboard_user;


--
-- Name: TABLE users; Type: ACL; Schema: auth; Owner: -
--

GRANT ALL ON TABLE auth.users TO dashboard_user;
GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE auth.users TO postgres;
GRANT SELECT ON TABLE auth.users TO postgres WITH GRANT OPTION;


--
-- Name: TABLE pg_stat_statements; Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON TABLE extensions.pg_stat_statements FROM postgres;
GRANT ALL ON TABLE extensions.pg_stat_statements TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE extensions.pg_stat_statements TO dashboard_user;


--
-- Name: TABLE pg_stat_statements_info; Type: ACL; Schema: extensions; Owner: -
--

REVOKE ALL ON TABLE extensions.pg_stat_statements_info FROM postgres;
GRANT ALL ON TABLE extensions.pg_stat_statements_info TO postgres WITH GRANT OPTION;
GRANT ALL ON TABLE extensions.pg_stat_statements_info TO dashboard_user;


--
-- Name: TABLE activity_logs; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.activity_logs TO anon;
GRANT ALL ON TABLE public.activity_logs TO authenticated;
GRANT ALL ON TABLE public.activity_logs TO service_role;


--
-- Name: SEQUENCE activity_logs_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.activity_logs_id_seq TO anon;
GRANT ALL ON SEQUENCE public.activity_logs_id_seq TO authenticated;
GRANT ALL ON SEQUENCE public.activity_logs_id_seq TO service_role;


--
-- Name: TABLE business_settings; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.business_settings TO anon;
GRANT ALL ON TABLE public.business_settings TO authenticated;
GRANT ALL ON TABLE public.business_settings TO service_role;


--
-- Name: TABLE customer_requests; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.customer_requests TO anon;
GRANT ALL ON TABLE public.customer_requests TO authenticated;
GRANT ALL ON TABLE public.customer_requests TO service_role;


--
-- Name: TABLE email_logs; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.email_logs TO anon;
GRANT ALL ON TABLE public.email_logs TO authenticated;
GRANT ALL ON TABLE public.email_logs TO service_role;


--
-- Name: TABLE organizations; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.organizations TO anon;
GRANT ALL ON TABLE public.organizations TO authenticated;
GRANT ALL ON TABLE public.organizations TO service_role;


--
-- Name: TABLE payment_method_options; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.payment_method_options TO anon;
GRANT ALL ON TABLE public.payment_method_options TO authenticated;
GRANT ALL ON TABLE public.payment_method_options TO service_role;


--
-- Name: SEQUENCE [redacted-token]; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.[redacted-token] TO anon;
GRANT ALL ON SEQUENCE public.[redacted-token] TO authenticated;
GRANT ALL ON SEQUENCE public.[redacted-token] TO service_role;


--
-- Name: TABLE payment_status_options; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.payment_status_options TO anon;
GRANT ALL ON TABLE public.payment_status_options TO authenticated;
GRANT ALL ON TABLE public.payment_status_options TO service_role;


--
-- Name: SEQUENCE [redacted-token]; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.[redacted-token] TO anon;
GRANT ALL ON SEQUENCE public.[redacted-token] TO authenticated;
GRANT ALL ON SEQUENCE public.[redacted-token] TO service_role;


--
-- Name: TABLE pricing_rules; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.pricing_rules TO anon;
GRANT ALL ON TABLE public.pricing_rules TO authenticated;
GRANT ALL ON TABLE public.pricing_rules TO service_role;


--
-- Name: TABLE request_stylists; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.request_stylists TO anon;
GRANT ALL ON TABLE public.request_stylists TO authenticated;
GRANT ALL ON TABLE public.request_stylists TO service_role;


--
-- Name: TABLE status_options; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.status_options TO anon;
GRANT ALL ON TABLE public.status_options TO authenticated;
GRANT ALL ON TABLE public.status_options TO service_role;


--
-- Name: SEQUENCE status_options_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON SEQUENCE public.status_options_id_seq TO anon;
GRANT ALL ON SEQUENCE public.status_options_id_seq TO authenticated;
GRANT ALL ON SEQUENCE public.status_options_id_seq TO service_role;


--
-- Name: TABLE stylist_availability; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.stylist_availability TO anon;
GRANT ALL ON TABLE public.stylist_availability TO authenticated;
GRANT ALL ON TABLE public.stylist_availability TO service_role;


--
-- Name: TABLE stylists; Type: ACL; Schema: public; Owner: -
--

GRANT ALL ON TABLE public.stylists TO anon;
GRANT ALL ON TABLE public.stylists TO authenticated;
GRANT ALL ON TABLE public.stylists TO service_role;


--
-- Name: TABLE messages; Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON TABLE realtime.messages TO postgres;
GRANT ALL ON TABLE realtime.messages TO dashboard_user;
GRANT SELECT,INSERT,UPDATE ON TABLE realtime.messages TO anon;
GRANT SELECT,INSERT,UPDATE ON TABLE realtime.messages TO authenticated;
GRANT SELECT,INSERT,UPDATE ON TABLE realtime.messages TO service_role;


--
-- Name: TABLE schema_migrations; Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON TABLE realtime.schema_migrations TO postgres;
GRANT ALL ON TABLE realtime.schema_migrations TO dashboard_user;
GRANT SELECT ON TABLE realtime.schema_migrations TO anon;
GRANT SELECT ON TABLE realtime.schema_migrations TO authenticated;
GRANT SELECT ON TABLE realtime.schema_migrations TO service_role;
GRANT ALL ON TABLE realtime.schema_migrations TO supabase_realtime_admin;


--
-- Name: TABLE subscription; Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON TABLE realtime.subscription TO postgres;
GRANT ALL ON TABLE realtime.subscription TO dashboard_user;
GRANT SELECT ON TABLE realtime.subscription TO anon;
GRANT SELECT ON TABLE realtime.subscription TO authenticated;
GRANT SELECT ON TABLE realtime.subscription TO service_role;
GRANT ALL ON TABLE realtime.subscription TO supabase_realtime_admin;


--
-- Name: SEQUENCE subscription_id_seq; Type: ACL; Schema: realtime; Owner: -
--

GRANT ALL ON SEQUENCE realtime.subscription_id_seq TO postgres;
GRANT ALL ON SEQUENCE realtime.subscription_id_seq TO dashboard_user;
GRANT USAGE ON SEQUENCE realtime.subscription_id_seq TO anon;
GRANT USAGE ON SEQUENCE realtime.subscription_id_seq TO authenticated;
GRANT USAGE ON SEQUENCE realtime.subscription_id_seq TO service_role;
GRANT ALL ON SEQUENCE realtime.subscription_id_seq TO supabase_realtime_admin;


--
-- Name: TABLE buckets; Type: ACL; Schema: storage; Owner: -
--

GRANT ALL ON TABLE storage.buckets TO anon;
GRANT ALL ON TABLE storage.buckets TO authenticated;
GRANT ALL ON TABLE storage.buckets TO service_role;
GRANT ALL ON TABLE storage.buckets TO postgres WITH GRANT OPTION;


--
-- Name: TABLE objects; Type: ACL; Schema: storage; Owner: -
--

GRANT ALL ON TABLE storage.objects TO anon;
GRANT ALL ON TABLE storage.objects TO authenticated;
GRANT ALL ON TABLE storage.objects TO service_role;
GRANT ALL ON TABLE storage.objects TO postgres WITH GRANT OPTION;


--
-- Name: TABLE s3_multipart_uploads; Type: ACL; Schema: storage; Owner: -
--

GRANT ALL ON TABLE storage.s3_multipart_uploads TO service_role;
GRANT SELECT ON TABLE storage.s3_multipart_uploads TO authenticated;
GRANT SELECT ON TABLE storage.s3_multipart_uploads TO anon;


--
-- Name: TABLE [redacted-token]; Type: ACL; Schema: storage; Owner: -
--

GRANT ALL ON TABLE storage.[redacted-token] TO service_role;
GRANT SELECT ON TABLE storage.[redacted-token] TO authenticated;
GRANT SELECT ON TABLE storage.[redacted-token] TO anon;


--
-- Name: TABLE secrets; Type: ACL; Schema: vault; Owner: -
--

GRANT SELECT,REFERENCES,DELETE,TRUNCATE ON TABLE vault.secrets TO postgres WITH GRANT OPTION;
GRANT SELECT,DELETE ON TABLE vault.secrets TO service_role;


--
-- Name: TABLE decrypted_secrets; Type: ACL; Schema: vault; Owner: -
--

GRANT SELECT,REFERENCES,DELETE,TRUNCATE ON TABLE vault.decrypted_secrets TO postgres WITH GRANT OPTION;
GRANT SELECT,DELETE ON TABLE vault.decrypted_secrets TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: auth; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_auth_admin IN SCHEMA auth GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_auth_admin IN SCHEMA auth GRANT ALL ON SEQUENCES TO dashboard_user;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: auth; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_auth_admin IN SCHEMA auth GRANT ALL ON FUNCTIONS TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_auth_admin IN SCHEMA auth GRANT ALL ON FUNCTIONS TO dashboard_user;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: auth; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_auth_admin IN SCHEMA auth GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_auth_admin IN SCHEMA auth GRANT ALL ON TABLES TO dashboard_user;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: extensions; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA extensions GRANT ALL ON SEQUENCES TO postgres WITH GRANT OPTION;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: extensions; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA extensions GRANT ALL ON FUNCTIONS TO postgres WITH GRANT OPTION;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: extensions; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA extensions GRANT ALL ON TABLES TO postgres WITH GRANT OPTION;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: graphql; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON SEQUENCES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON SEQUENCES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON SEQUENCES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: graphql; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON FUNCTIONS TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON FUNCTIONS TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON FUNCTIONS TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON FUNCTIONS TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: graphql; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON TABLES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON TABLES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql GRANT ALL ON TABLES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: graphql_public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON SEQUENCES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON SEQUENCES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON SEQUENCES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: graphql_public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON FUNCTIONS TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON FUNCTIONS TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON FUNCTIONS TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON FUNCTIONS TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: graphql_public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON TABLES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON TABLES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA graphql_public GRANT ALL ON TABLES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON SEQUENCES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON SEQUENCES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON SEQUENCES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON SEQUENCES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON SEQUENCES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON SEQUENCES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON FUNCTIONS TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON FUNCTIONS TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON FUNCTIONS TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON FUNCTIONS TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON FUNCTIONS TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON FUNCTIONS TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON FUNCTIONS TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: public; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON TABLES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON TABLES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public GRANT ALL ON TABLES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: realtime; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA realtime GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA realtime GRANT ALL ON SEQUENCES TO dashboard_user;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: realtime; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA realtime GRANT ALL ON FUNCTIONS TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA realtime GRANT ALL ON FUNCTIONS TO dashboard_user;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: realtime; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA realtime GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA realtime GRANT ALL ON TABLES TO dashboard_user;


--
-- Name: DEFAULT PRIVILEGES FOR SEQUENCES; Type: DEFAULT ACL; Schema: storage; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON SEQUENCES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON SEQUENCES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON SEQUENCES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON SEQUENCES TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR FUNCTIONS; Type: DEFAULT ACL; Schema: storage; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON FUNCTIONS TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON FUNCTIONS TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON FUNCTIONS TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON FUNCTIONS TO service_role;


--
-- Name: DEFAULT PRIVILEGES FOR TABLES; Type: DEFAULT ACL; Schema: storage; Owner: -
--

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON TABLES TO postgres;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON TABLES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON TABLES TO authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA storage GRANT ALL ON TABLES TO service_role;


--
-- Name: [redacted-token]; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER [redacted-token] ON sql_drop
         WHEN TAG IN ('DROP EXTENSION')
   EXECUTE FUNCTION extensions.set_graphql_placeholder();


--
-- Name: issue_pg_cron_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_cron_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_cron_access();


--
-- Name: issue_pg_graphql_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_graphql_access ON ddl_command_end
         WHEN TAG IN ('CREATE FUNCTION')
   EXECUTE FUNCTION extensions.grant_pg_graphql_access();


--
-- Name: issue_pg_net_access; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER issue_pg_net_access ON ddl_command_end
         WHEN TAG IN ('CREATE EXTENSION')
   EXECUTE FUNCTION extensions.grant_pg_net_access();


--
-- Name: pgrst_ddl_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_ddl_watch ON ddl_command_end
   EXECUTE FUNCTION extensions.pgrst_ddl_watch();


--
-- Name: pgrst_drop_watch; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER pgrst_drop_watch ON sql_drop
   EXECUTE FUNCTION extensions.pgrst_drop_watch();


--
-- PostgreSQL database dump complete
--

