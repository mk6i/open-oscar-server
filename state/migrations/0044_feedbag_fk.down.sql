ALTER TABLE feedbag
    RENAME TO feedbag_new;

CREATE TABLE feedbag
(
    screenName   VARCHAR(16),
    groupID      INTEGER,
    itemID       INTEGER,
    classID      INTEGER,
    name         TEXT,
    attributes   BLOB,
    lastModified INTEGER,
    pdMode       INT              DEFAULT 0,
    authPending  BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (screenName, groupID, itemID)
);

INSERT INTO feedbag (screenName, groupID, itemID, classID, name, attributes, lastModified, pdMode, authPending)
SELECT screenName, groupID, itemID, classID, name, attributes, lastModified, pdMode, authPending
FROM feedbag_new;

DROP TABLE feedbag_new;
