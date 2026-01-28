ALTER TABLE users
    ADD COLUMN icq_permissions_webAware BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users
    ADD COLUMN icq_permissions_allowSpam BOOLEAN NOT NULL DEFAULT false;
