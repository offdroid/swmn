DROP TABLE users;
DROP TABLE clients;

DROP TRIGGER IF EXISTS clients_fts_before_update;
DROP TRIGGER IF EXISTS clients_fts_before_delete;
DROP TRIGGER IF EXISTS clients_after_update;
DROP TRIGGER IF EXISTS clients_after_insert;
