-- Denormalized buddy authorization-pending flag (TLV 0x0066 on buddy items).
-- Maintained by FeedbagUpsert; no backfill of historical rows.
ALTER TABLE feedbag
	ADD COLUMN authPending BOOLEAN NOT NULL DEFAULT FALSE;
