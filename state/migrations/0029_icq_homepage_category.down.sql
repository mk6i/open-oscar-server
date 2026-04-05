-- Remove homepage category columns for ICQ users

ALTER TABLE users
    DROP COLUMN icq_homepageCategory_enabled;
ALTER TABLE users
    DROP COLUMN icq_homepageCategory_index;
ALTER TABLE users
    DROP COLUMN icq_homepageCategory_description;
