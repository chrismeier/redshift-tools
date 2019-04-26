#!/usr/bin/env python
import argparse
import psycopg2
import os

def setup_views(cur, conn):
  generate_permissions_view_sql = """CREATE OR REPLACE VIEW admin.v_generate_user_grant_revoke_ddl AS
  WITH objprivs AS (
    SELECT objowner,
    schemaname,
    objname,
    objtype,
    CASE WHEN split_part(aclstring,'=',1)='' THEN 'PUBLIC' ELSE translate(trim(split_part(aclstring,'=',1)),'"','') END::text AS grantee,
    translate(trim(split_part(aclstring,'/',2)),'"','')::text AS grantor,
    trim(split_part(split_part(aclstring,'=',2),'/',1))::text AS privilege,
    CASE WHEN objtype = 'default acl' THEN objname
    WHEN objtype = 'function' AND regexp_instr(schemaname,'[^a-z]') > 0 THEN objname
    WHEN objtype = 'function' THEN QUOTE_IDENT(schemaname)||'.'||objname
    ELSE nvl(QUOTE_IDENT(schemaname)||'.'||QUOTE_IDENT(objname),QUOTE_IDENT(objname)) END::text as fullobjname,
    CASE WHEN split_part(aclstring,'=',1)='' THEN 'PUBLIC'
    ELSE trim(split_part(aclstring,'=',1))
    END::text as splitgrantee,
    grantseq
    FROM (
      -- TABLE AND VIEW privileges
      SELECT pg_get_userbyid(b.relowner)::text AS objowner,
      trim(c.nspname)::text AS schemaname,
      b.relname::text AS objname,
      CASE WHEN relkind='r' THEN 'table' ELSE 'view' END::text AS objtype,
      TRIM(SPLIT_PART(array_to_string(b.relacl,','), ',', NS.n))::text AS aclstring,
      NS.n as grantseq
      FROM
      (SELECT oid,generate_series(1,array_upper(relacl,1))  AS n FROM pg_class) NS
      inner join pg_class B ON b.oid = ns.oid AND  NS.n <= array_upper(b.relacl,1)
      join pg_namespace c on b.relnamespace = c.oid
      where relkind in ('r','v')
      UNION ALL
      -- SCHEMA privileges
      SELECT pg_get_userbyid(b.nspowner)::text AS objowner,
      null::text AS schemaname,
      b.nspname::text AS objname,
      'schema'::text AS objtype,
      TRIM(SPLIT_PART(array_to_string(b.nspacl,','), ',', NS.n))::text AS aclstring,
      NS.n as grantseq
      FROM
      (SELECT oid,generate_series(1,array_upper(nspacl,1)) AS n FROM pg_namespace) NS
      inner join pg_namespace B ON b.oid = ns.oid AND NS.n <= array_upper(b.nspacl,1)
      UNION ALL
      -- DATABASE privileges
      SELECT pg_get_userbyid(b.datdba)::text AS objowner,
      null::text AS schemaname,
      b.datname::text AS objname,
      'database'::text AS objtype,
      TRIM(SPLIT_PART(array_to_string(b.datacl,','), ',', NS.n))::text AS aclstring,
      NS.n as grantseq
      FROM
      (SELECT oid,generate_series(1,array_upper(datacl,1)) AS n FROM pg_database) NS
      inner join pg_database B ON b.oid = ns.oid AND NS.n <= array_upper(b.datacl,1)
      UNION ALL
      -- FUNCTION privileges
      SELECT pg_get_userbyid(b.proowner)::text AS objowner,
      trim(c.nspname)::text AS schemaname,
      textin(regprocedureout(b.oid::regprocedure))::text AS objname,
      'function'::text AS objtype,
      TRIM(SPLIT_PART(array_to_string(b.proacl,','), ',', NS.n))::text AS aclstring,
      NS.n as grantseq
      FROM
      (SELECT oid,generate_series(1,array_upper(proacl,1)) AS n FROM pg_proc) NS
      inner join pg_proc B ON b.oid = ns.oid and NS.n <= array_upper(b.proacl,1)
      join pg_namespace c on b.pronamespace=c.oid
      UNION ALL
      -- LANGUAGE privileges
      SELECT null::text AS objowner,
      null::text AS schemaname,
      lanname::text AS objname,
      'language'::text AS objtype,
      TRIM(SPLIT_PART(array_to_string(b.lanacl,','), ',', NS.n))::text AS aclstring,
      NS.n as grantseq
      FROM
      (SELECT oid,generate_series(1,array_upper(lanacl,1)) AS n FROM pg_language) NS
      inner join pg_language B ON b.oid = ns.oid and NS.n <= array_upper(b.lanacl,1)
      UNION ALL
      -- DEFAULT ACL privileges
      SELECT pg_get_userbyid(b.defacluser)::text AS objowner,
      trim(c.nspname)::text AS schemaname,
      decode(b.defaclobjtype,'r','tables','f','functions')::text AS objname,
      'default acl'::text AS objtype,
      TRIM(SPLIT_PART(array_to_string(b.defaclacl,','), ',', NS.n))::text AS aclstring,
      NS.n as grantseq
      FROM
      (SELECT oid,generate_series(1,array_upper(defaclacl,1)) AS n FROM pg_default_acl) NS
      join pg_default_acl b ON b.oid = ns.oid and NS.n <= array_upper(b.defaclacl,1)
      left join  pg_namespace c on b.defaclnamespace=c.oid
    )
    where  (split_part(aclstring,'=',1) <> split_part(aclstring,'/',2)
    and split_part(aclstring,'=',1) <> 'rdsdb'
    and NOT (split_part(aclstring,'=',1)='' AND split_part(aclstring,'/',2) = 'rdsdb'))
  )
  -- Extract object GRANTS
  SELECT objowner, schemaname, objname, objtype, grantor, grantee, 'grant' AS ddltype, grantseq,
  decode(objtype,'database',0,'schema',1,'language',1,'table',2,'view',2,'function',2,'default acl',3) AS objseq,
  CASE WHEN (grantor <> current_user AND grantor <> 'rdsdb' AND objtype <> 'default acl') THEN 'SET SESSION AUTHORIZATION '||QUOTE_IDENT(grantor)||';' ELSE '' END::text||
  (CASE WHEN privilege = 'arwdRxt' OR privilege = 'a*r*w*d*R*x*t*' THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT ALL on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN privilege = 'a*r*w*d*R*x*t*' THEN ' with grant option;' ELSE ';' END::text)
  when privilege = 'UC' OR privilege = 'U*C*' THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT ALL on '||objtype||' '||fullobjname||' to '||splitgrantee||
  (CASE WHEN privilege = 'U*C*' THEN ' with grant option;' ELSE ';' END::text)
  when privilege = 'CT' OR privilege = 'U*C*' THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT ALL on '||objtype||' '||fullobjname||' to '||splitgrantee||
  (CASE WHEN privilege = 'C*T*' THEN ' with grant option;' ELSE ';' END::text)
  ELSE
  (
  CASE WHEN charindex('a',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT INSERT on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('a*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('r',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT SELECT on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('r*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('w',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT UPDATE on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('w*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('d',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT DELETE on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('d*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('R',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT RULE on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('R*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('x',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT REFERENCES on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('x*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('t',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT TRIGGER on '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('t*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('U',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT USAGE on '||objtype||' '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('U*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('C',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT CREATE on '||objtype||' '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('C*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('T',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT TEMP on '||objtype||' '||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('T*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text||
  CASE WHEN charindex('X',privilege) > 0 THEN (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ELSE '' END::text)||'GRANT EXECUTE on '||
  (CASE WHEN objtype = 'default acl' THEN '' ELSE objtype||' ' END::text)||fullobjname||' to '||splitgrantee||
  (CASE WHEN charindex('X*',privilege) > 0 THEN ' with grant option;' ELSE ';' END::text) ELSE '' END::text
  ) END::text)||
  CASE WHEN (grantor <> current_user AND grantor <> 'rdsdb' AND objtype <> 'default acl') THEN 'RESET SESSION AUTHORIZATION;' ELSE '' END::text AS ddl
  FROM objprivs
  UNION ALL
  -- Extract object REVOKES
  SELECT objowner, schemaname, objname, objtype, grantor, grantee, 'revoke'::text AS ddltype, grantseq,
  decode(objtype,'default acl',0,'function',1,'table',1,'view',1,'schema',2,'language',2,'database',3) AS objseq,
  CASE WHEN (grantor <> current_user AND grantor <> 'rdsdb' AND objtype <> 'default acl' AND grantor <> objowner) THEN 'SET SESSION AUTHORIZATION '||QUOTE_IDENT(grantor)||';' ELSE '' END::text||
  (CASE WHEN objtype = 'default acl' THEN 'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(grantor)||nvl(' in schema '||QUOTE_IDENT(schemaname)||' ',' ')
  ||'REVOKE ALL on '||fullobjname||' FROM '||splitgrantee||';'
  ELSE 'REVOKE ALL on '||(CASE WHEN objtype = 'table' OR objtype = 'view' THEN '' ELSE objtype||' ' END::text)||fullobjname||' FROM '||splitgrantee||';' END::text)||
  CASE WHEN (grantor <> current_user AND grantor <> 'rdsdb' AND objtype <> 'default acl' AND grantor <> objowner) THEN 'RESET SESSION AUTHORIZATION;' ELSE '' END::text AS ddl
  FROM objprivs
  WHERE NOT (objtype = 'default acl' AND grantee = 'PUBLIC' and objname='functions')
  UNION ALL
  -- Eliminate empty default ACLs
  SELECT null::text AS objowner, null::text AS schemaname, decode(b.defaclobjtype,'r','tables','f','functions')::text AS objname,
      'default acl'::text AS objtype,  pg_get_userbyid(b.defacluser)::text AS grantor, null::text AS grantee, 'revoke'::text AS ddltype, 5 as grantseq, 5 AS objseq,
    'ALTER DEFAULT PRIVILEGES for user '||QUOTE_IDENT(pg_get_userbyid(b.defacluser))||' GRANT ALL on '||decode(b.defaclobjtype,'r','tables','f','functions')||' TO '||QUOTE_IDENT(pg_get_userbyid(b.defacluser))||
  CASE WHEN b.defaclobjtype = 'f' then ', PUBLIC;' ELSE ';' END::text AS ddl FROM pg_default_acl b where b.defaclnamespace=0;"""

  cur.execute(generate_permissions_view_sql)
  conn.commit() 

  drop_objs_view = """
  CREATE OR REPLACE VIEW admin.v_find_dropuser_objs as
  SELECT owner.objtype,
        owner.objowner,
        owner.userid,
        owner.schemaname,
        owner.objname,
        owner.ddl
  FROM (
  -- Functions owned by the user
      SELECT 'Function',pgu.usename,pgu.usesysid,nc.nspname,textin (regprocedureout (pproc.oid::regprocedure)),
      'alter function ' || QUOTE_IDENT(nc.nspname) || '.' ||textin (regprocedureout (pproc.oid::regprocedure)) || ' owner to '
      FROM pg_proc pproc,pg_user pgu,pg_namespace nc
  WHERE pproc.pronamespace = nc.oid
  AND   pproc.proowner = pgu.usesysid
  UNION ALL
  -- Databases owned by the user
  SELECT 'Database',
        pgu.usename,
        pgu.usesysid,
        NULL,
        pgd.datname,
        'alter database ' || QUOTE_IDENT(pgd.datname) || ' owner to '
  FROM pg_database pgd,
      pg_user pgu
  WHERE pgd.datdba = pgu.usesysid
  UNION ALL
  -- Schemas owned by the user
  SELECT 'Schema',
        pgu.usename,
        pgu.usesysid,
        NULL,
        pgn.nspname,
        'alter schema '|| QUOTE_IDENT(pgn.nspname) ||' owner to '
  FROM pg_namespace pgn,
      pg_user pgu
  WHERE pgn.nspowner = pgu.usesysid
  UNION ALL
  -- Tables or Views owned by the user
  SELECT decode(pgc.relkind,
              'r','Table',
              'v','View'
        ) ,
        pgu.usename,
        pgu.usesysid,
        nc.nspname,
        pgc.relname,
        'alter table ' || QUOTE_IDENT(nc.nspname) || '.' || QUOTE_IDENT(pgc.relname) || ' owner to '
  FROM pg_class pgc,
      pg_user pgu,
      pg_namespace nc
  WHERE pgc.relnamespace = nc.oid
  AND   pgc.relkind IN ('r','v')
  AND   pgu.usesysid = pgc.relowner
  AND   nc.nspname NOT ILIKE 'pg\_temp\_%'
  UNION ALL
  -- Python libraries owned by the user
  SELECT 'Library',
        pgu.usename,
        pgu.usesysid,
        '',
        pgl.name,
        'No DDL avaible for Python Library. You should DROP OR REPLACE the Python Library'
  FROM  pg_library pgl,
        pg_user pgu
  WHERE pgl.owner = pgu.usesysid) OWNER ("objtype","objowner","userid","schemaname","objname","ddl")
  WHERE owner.userid > 1;
  """
  cur.execute(drop_objs_view)
  conn.commit()


def revoke_all_for_user_sql(cur, user, conn_user):
  revokes = [] 
  cur.execute(f"select ddl from admin.v_generate_user_grant_revoke_ddl where grantee = '{user}' and ddl like '%REVOKE%';")
  rows = cur.fetchall()
  if rows:
    revokes = revokes + [revoke[0] for revoke in rows]
  cur.execute(f"select ddl from admin.v_find_dropuser_objs where objowner = '{user}' ;")
  rows = cur.fetchall()
  if rows:
    for revoke in rows:
      if 'No DDL avaible' not in revoke[0]:
        revokes.append(revoke[0] + ' ' + conn_user + ';')
      else:
        print(revoke[0])
  return revokes


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='''This script removes privileges on objects, transfers ownership to connection user, and finally drops specified user.
                                                  
                                                  Before use, export the following vars:
                                                    export RS_CONN_USER=[yourPrivilegedUser]
                                                    export RS_CONN_PASSWORD=[yourPrivilegedPassword]
                                                ''')

  parser.add_argument('--host', required=True, help='the host for connection')
  parser.add_argument('--port', help='the port database for connection', required=True)
  parser.add_argument('--db', help='the database for connection', required=True)
  parser.add_argument('--user_to_drop', help='the Redshift user to be dropped', required=True)
  args = parser.parse_args()
  args_dict = vars(args)

  conn = psycopg2.connect(f"dbname='{args_dict['db']}' user='{os.environ.get('RS_CONN_USER')}' host='{args_dict['host']}' password='{os.environ.get('RS_CONN_PASSWORD')}' port={args_dict['port']}")
  cur = conn.cursor()

  sql_statements = []
  sql_statements = revoke_all_for_user_sql(cur, args_dict['user_to_drop'], os.environ.get('RS_CONN_USER'))
  sql_statements.append(f"DROP USER {args_dict['user_to_drop']};")
  sql_statements = [i for i in sql_statements if i]
  [print("\n", sql) for sql in sql_statements]
  [(cur.execute(sql), conn.commit()) for sql in sql_statements]