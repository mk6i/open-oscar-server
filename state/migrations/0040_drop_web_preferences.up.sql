-- Web API preferences are now stored as OSCAR buddy prefs in the feedbag,
-- so the standalone web_preferences table is no longer used.
DROP INDEX IF EXISTS idx_web_preferences_screen_name;
DROP TABLE IF EXISTS web_preferences;
