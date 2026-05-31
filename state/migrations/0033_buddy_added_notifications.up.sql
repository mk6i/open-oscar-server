-- Dedupe for ICQ "you were added" notifications (SSI SNAC(13,1C)).
-- A row means: requesterScreenName was added to granterScreenName's list.
CREATE TABLE IF NOT EXISTS buddyAddedNotifications
(
    granterScreenName   VARCHAR(16) NOT NULL,
    requesterScreenName VARCHAR(16) NOT NULL,
    createdAt           INTEGER     NOT NULL,
    PRIMARY KEY (granterScreenName, requesterScreenName),
    FOREIGN KEY (granterScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (requesterScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);
