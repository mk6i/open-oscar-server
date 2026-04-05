-- Add homepage category columns for ICQ users
-- From iserverd: hpage_cf (enabled), hpage_cat (index), hpage_txt (description)
-- Used by V5 META_SET_HPCAT (0x0442) command

ALTER TABLE users
    ADD COLUMN icq_homepageCategory_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users
    ADD COLUMN icq_homepageCategory_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users
    ADD COLUMN icq_homepageCategory_description TEXT NOT NULL DEFAULT '';
