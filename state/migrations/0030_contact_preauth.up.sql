-- Pre-authorization grants: owner may allow requester to add owner as a buddy
-- when owner requires authorization (ICQ first; table is protocol-agnostic).
CREATE TABLE contactPreauth
(
    ownerScreenName        VARCHAR(16) NOT NULL,
    authorizedScreenName   VARCHAR(16) NOT NULL,
    createdAt              INTEGER     NOT NULL,
    PRIMARY KEY (ownerScreenName, authorizedScreenName),
    FOREIGN KEY (ownerScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (authorizedScreenName) REFERENCES users (identScreenName) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX idx_contactPreauth_authorizedScreenName ON contactPreauth (authorizedScreenName);
