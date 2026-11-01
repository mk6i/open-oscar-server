ALTER TABLE users
    DROP COLUMN icq_permissions_webAware;
ALTER TABLE users
    ADD COLUMN icq_permissions_webAware BOOLEAN NOT NULL DEFAULT false;
