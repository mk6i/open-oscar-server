-- Deleting a user deletes their feedbag. Rows that belong to no user are
-- dropped, since they would violate the foreign key.
-- classID 24 is wire.FeedbagClassIdAlInfo (linked account).
ALTER TABLE feedbag
    RENAME TO feedbag_old;

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
    UNIQUE (screenName, groupID, itemID),
    FOREIGN KEY (screenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO feedbag (screenName, groupID, itemID, classID, name, attributes, lastModified, pdMode, authPending)
SELECT screenName, groupID, itemID, classID, name, attributes, lastModified, pdMode, authPending
FROM feedbag_old
WHERE screenName IN (SELECT identScreenName FROM users);

DROP TABLE feedbag_old;

-- Linked-account items whose target no longer exists would otherwise grant
-- access to whoever registers that screen name next.
DELETE FROM feedbag
WHERE classID = 24
  AND name NOT IN (SELECT identScreenName FROM users);
