-- D390 (#500): the account look gains `themeChosen`. A look saved before this
-- migration was written by a page that stored the theme it first showed, so
-- nobody's saved theme may change: every existing look is marked chosen. A look
-- that has no flag afterwards is one a new account never chose a theme for, and
-- follows each device's light or dark setting. Accounts with no look keep none.
-- The saved heads and snapshots carry the document; the operation tail carries
-- `look.set` intents that clients replay, and those get the flag too.
UPDATE canvas_heads
SET document = json_set(document, '$.look.themeChosen', json('true'))
WHERE json_valid(document)
  AND json_type(document, '$.look') = 'object'
  AND json_type(document, '$.look.themeChosen') IS NULL;

UPDATE canvas_snapshots
SET document = json_set(document, '$.look.themeChosen', json('true'))
WHERE json_valid(document)
  AND json_type(document, '$.look') = 'object'
  AND json_type(document, '$.look.themeChosen') IS NULL;

UPDATE canvas_operations
SET event = json_set(event, '$.intent.look.themeChosen', json('true'))
WHERE json_valid(event)
  AND json_extract(event, '$.intent.type') = 'look.set'
  AND json_type(event, '$.intent.look') = 'object'
  AND json_type(event, '$.intent.look.themeChosen') IS NULL;
