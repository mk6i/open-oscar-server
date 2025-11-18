ALTER TABLE offlineMessage
    RENAME TO offlineMessage_old;

CREATE TABLE offlineMessage
(
    sender    VARCHAR(16) NOT NULL,
    recipient VARCHAR(16) NOT NULL,
    message   BLOB        NOT NULL,
    sent      TIMESTAMP   NOT NULL,
    FOREIGN KEY (sender) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (recipient) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO offlineMessage (sender, recipient, message, sent)
SELECT sender, recipient, message, sent
FROM offlineMessage_old;

DROP TABLE offlineMessage_old;

CREATE INDEX idx_offlineMessage_sender ON offlineMessage (sender);
CREATE INDEX idx_offlineMessage_recipient ON offlineMessage (recipient);

ALTER TABLE users
    ADD COLUMN offlineMsgCount INTEGER NOT NULL DEFAULT 0;
