ALTER TABLE users
    DROP COLUMN offlineMsgCount;

DROP INDEX IF EXISTS idx_offlineMessage_sender;
DROP INDEX IF EXISTS idx_offlineMessage_recipient;

ALTER TABLE offlineMessage
    RENAME TO offlineMessage_new;

CREATE TABLE offlineMessage
(
    sender    VARCHAR(16) NOT NULL,
    recipient VARCHAR(16) NOT NULL,
    message   BLOB        NOT NULL,
    sent      TIMESTAMP   NOT NULL
);

INSERT INTO offlineMessage (sender, recipient, message, sent)
SELECT sender, recipient, message, sent
FROM offlineMessage_new;

DROP TABLE offlineMessage_new;
