-- Run once against an existing PostgreSQL database after backing it up.
-- First inspect the current rows. If the former CLIENT row was already
-- changed to COMPANY, change that specific row back to PERSON manually.
-- SELECT id, name, entity_type FROM entities ORDER BY id;

UPDATE entities SET entity_type = 'PERSON' WHERE entity_type = 'CLIENT';
UPDATE entities SET entity_type = 'COMPANY' WHERE entity_type = 'AGENCY';

ALTER TABLE entities DROP CONSTRAINT IF EXISTS entities_entity_type_check;
ALTER TABLE entities
    ADD CONSTRAINT entities_entity_type_check
    CHECK (entity_type IN ('PERSON', 'COMPANY'));
