-- ICQ "originally from" home town (SetICQInfo TLVs 0x0320 / 0x032A / 0x0334).
ALTER TABLE users ADD COLUMN icq_basicInfo_originCity TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN icq_basicInfo_originState TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN icq_basicInfo_originCountryCode INTEGER NOT NULL DEFAULT 0;
