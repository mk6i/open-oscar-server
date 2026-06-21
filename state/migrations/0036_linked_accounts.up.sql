CREATE TABLE IF NOT EXISTS linkedAccounts
(
    identScreenName     VARCHAR(16),
    linkedScreenName    VARCHAR(16),
    PRIMARY KEY (identScreenName, linkedScreenName),
    CHECK (identScreenName != linkedScreenName),
    FOREIGN KEY (identScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE,
    FOREIGN KEY (linkedScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE
);
