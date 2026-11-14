-- D170-shaped rows for a fully migrated server database (J438, #473): 50 users, 4,000 live and
-- 4,000 expired sessions, 1,000 hosts with certificates and bootstrap rows, 200 terminals,
-- a ~6 KB layout document per user with 64 journalled ops, 100,000 receipts, 2,500 tombstones.
-- Used by the db_pool_bench example and the D379 migration-compatibility tests.
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<49)
INSERT INTO users(id,name,owner,recovery_hash,username,display_name,recovery_version,recovery_wrap_version)
SELECT printf('u%02d',i), 'User '||i, CASE WHEN i=0 THEN 1 ELSE 0 END, hex(randomblob(32)), 'user'||i, 'User Number '||i, 2, 2 FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<99)
INSERT INTO passkeys(id,user_id,credential,aaguid) SELECT printf('pk-u%02d-%d',i/2,i%2), printf('u%02d',i/2), hex(randomblob(300)), 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<7999)
INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked,passkey_id,login_sequence)
SELECT 'tok-'||i, printf('u%02d',i%50), 'iPhone Safari '||i, CASE WHEN i<4000 THEN 1800000000+86400*20 ELSE 1700000000 END, 1799990000, 1, printf('pk-u%02d-0',i%50), i FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<999)
INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at,hostname)
SELECT unhex(printf('%032x',i+1)), printf('u%02d',i%10), 'rootful', 0, 1700000000, 'host-'||i FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<999)
INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after)
SELECT unhex(printf('%064x',i+1)), unhex(printf('%032x',i+1)), randomblob(32), randomblob(32), 1799999000, 1799999000+604800 FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<999)
INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup,os)
SELECT unhex(printf('%032x',i+1)), 'root@10.1.'||(i/250)||'.'||(i%250), 'lookup-'||i, 'Debian GNU/Linux 13' FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<19)
INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) SELECT unhex(printf('%032x',i*50+1)), printf('u%02d',(i*50)%10), 1 FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<199)
INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) SELECT unhex(printf('%032x',100000+i)), printf('u%02d',i%50), 1799990000, 1799999000 FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<49)
INSERT INTO canvas_heads(account,revision,document,initialized)
SELECT printf('u%02d',i), 64, '{"revision":64,"views":"'||hex(zeroblob(3000))||'"}', 1 FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<3199)
INSERT INTO canvas_operations(account,revision,event)
SELECT printf('u%02d',i/64), i%64+1, '{"type":"canvas.layout.operation","revision":'||(i%64+1)||',"op_id":"seed-'||i||'","intent":{"type":"move","window_id":"w-'||(i%7)||'","x":120,"y":80},"noop":false}' FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<99999)
INSERT INTO canvas_receipts(account,op_id,request,revision)
SELECT printf('u%02d',i%50), 'seed-op-'||i, hex(randomblob(32)), 1+(i/50)%64 FROM n;
WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i<2499)
INSERT INTO canvas_closed(account,window_id) SELECT printf('u%02d',i%50), 'closed-'||i FROM n;
