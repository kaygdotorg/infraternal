-- D339 (#337): a machine with no usable hostname is called `<os>-<first 6 characters of its host id>`, not
-- `unnamed` / `unnamed-<n>` (migration 0029). Rename the stored placeholders once, audited like any automatic
-- rename. Only placeholders move: a name a person picked (`hand`) or any real hostname stays exactly as it is.
--
-- The os word mirrors `fallback_machine_name` in infraternal-plugin-api (macos, windows, freebsd, linux, else host).
-- A collision takes `-2` … `-9` (the first free), the same stable rule naming uses at runtime: placeholders sharing a
-- base are ranked by node id (the lowest keeps the bare base), and a retained name moves a candidate to the next
-- suffix. A placeholder this cannot rename (a clash beyond `-9`) keeps its old label and is renamed at its next attach.
CREATE TEMP TABLE _fallback_labels(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE);
WITH RECURSIVE named(id,name) AS (
    SELECT n.id,
           CASE
               WHEN lower(COALESCE(b.os,'')) LIKE '%mac%' OR lower(COALESCE(b.os,'')) LIKE '%darwin%' THEN 'macos'
               WHEN lower(COALESCE(b.os,'')) LIKE '%windows%' THEN 'windows'
               WHEN lower(COALESCE(b.os,'')) LIKE '%bsd%' THEN 'freebsd'
               WHEN lower(COALESCE(b.os,'')) LIKE '%linux%' OR lower(COALESCE(b.os,'')) LIKE '%debian%'
                    OR lower(COALESCE(b.os,'')) LIKE '%ubuntu%' THEN 'linux'
               ELSE 'host'
           END || '-' || substr(replace(lower(n.dataplane_host),'-',''),1,6)
    FROM mesh_nodes n
    LEFT JOIN remote_host_bootstrap b ON lower(hex(b.host_id))=replace(lower(n.dataplane_host),'-','')
    WHERE n.name_source='placeholder' AND n.dataplane_host IS NOT NULL AND n.dataplane_host!='server'
      AND (n.name='unnamed' OR n.name GLOB 'unnamed-[0-9]*')
), ranked(id,base,n) AS (
    SELECT id,name,row_number() OVER (PARTITION BY name ORDER BY id) FROM named
), candidates(id,base,n,name) AS (
    SELECT id,base,n,CASE n WHEN 1 THEN base ELSE base||'-'||n END FROM ranked
    UNION ALL
    SELECT id,base,n+1,base||'-'||(n+1) FROM candidates
    WHERE n<9 AND EXISTS(SELECT 1 FROM mesh_nodes m WHERE m.name=candidates.name COLLATE NOCASE)
)
INSERT OR IGNORE INTO _fallback_labels
SELECT id,name FROM candidates c
WHERE NOT EXISTS(SELECT 1 FROM mesh_nodes m WHERE m.name=c.name COLLATE NOCASE)
ORDER BY id,n;

UPDATE mesh_state SET revision=revision+1
WHERE singleton=1 AND EXISTS(SELECT 1 FROM _fallback_labels);
INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json)
SELECT u.id,'mesh.node.name',CAST(n.id AS TEXT),s.revision,unixepoch(),
       json_object('node_id',n.id,'name',l.name,'previous',n.name,
                   'source','placeholder','automatic',json('true'))
FROM mesh_nodes n JOIN _fallback_labels l ON l.id=n.id
JOIN (SELECT id FROM users WHERE owner=1 ORDER BY rowid LIMIT 1) u
JOIN mesh_state s ON s.singleton=1;
UPDATE mesh_nodes SET name=(SELECT name FROM _fallback_labels WHERE id=mesh_nodes.id)
WHERE id IN(SELECT id FROM _fallback_labels);
DROP TABLE _fallback_labels;
