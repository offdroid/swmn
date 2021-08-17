CREATE TABLE users(
    name TEXT PRIMARY KEY NOT NULL,
    password TEXT NOT NULL,
    disabled BOOLEAN DEFAULT false
);

CREATE TABLE clients(
    id TEXT NOT NULL PRIMARY KEY,
    description TEXT,
    associated_with TEXT,
    date_created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    creator_id TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY(creator_id) REFERENCES users(name)
);

CREATE VIRTUAL TABLE clients_fts USING fts5(id, description, associated_with, creator_id);

-- Based on https://forum.xojo.com/t/sqlite-fts5-how-to-stay-in-sync-virtual-table-with-the-database/55938/9 from Richard Duke
DROP TRIGGER IF EXISTS clients_fts_before_update;
CREATE TRIGGER clients_fts_before_update 
BEFORE UPDATE ON clients BEGIN
    DELETE FROM clients_fts WHERE id=old.id;
END;

DROP TRIGGER IF EXISTS clients_fts_before_delete;
CREATE TRIGGER clients_fts_before_delete 
BEFORE DELETE ON clients BEGIN
    DELETE FROM clients_fts WHERE id=old.id;
END;

DROP TRIGGER IF EXISTS clients_after_update;
CREATE TRIGGER clients_after_update 
AFTER UPDATE ON clients BEGIN
    INSERT INTO clients_fts (id, description, associated_with, creator_id) 
    SELECT id, description, associated_with, creator_id
    FROM clients 
    WHERE new.id = clients.id;
END;

DROP TRIGGER IF EXISTS clients_after_insert;
CREATE TRIGGER clients_after_insert 
AFTER INSERT ON clients BEGIN
    INSERT INTO clients_fts (id, description, associated_with, creator_id) 
    SELECT id, description, associated_with, creator_id
    FROM clients 
    WHERE new.id = clients.id;
END;
