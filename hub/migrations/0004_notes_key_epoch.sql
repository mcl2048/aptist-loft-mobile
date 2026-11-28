ALTER TABLE hub_notes ADD COLUMN key_epoch TEXT CHECK (length(key_epoch) = 22);
ALTER TABLE hub_notes ADD COLUMN reset_revision INTEGER CHECK (reset_revision BETWEEN 1 AND revision);
ALTER TABLE hub_notes ADD COLUMN reset_fingerprint TEXT CHECK (length(reset_fingerprint) = 43);
