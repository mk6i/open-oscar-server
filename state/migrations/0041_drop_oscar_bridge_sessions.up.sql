-- The WebAPI-to-OSCAR bridge mapping (aimsid -> cookie/host/port) is now held
-- in-memory on the WebAPISession, so this table is no longer used.
DROP TABLE IF EXISTS oscar_bridge_sessions;
