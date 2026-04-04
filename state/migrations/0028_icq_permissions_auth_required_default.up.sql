ALTER TABLE users
    DROP COLUMN icq_permissions_authRequired;
ALTER TABLE users
    ADD COLUMN icq_permissions_authRequired BOOLEAN NOT NULL DEFAULT true;
