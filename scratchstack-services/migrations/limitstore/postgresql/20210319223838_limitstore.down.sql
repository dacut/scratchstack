-- Undo the limitstore tables and schema.
DROP TABLE limitstore.account_limit;
DROP SEQUENCE limitstore.seq_limit_id;
DROP TABLE limitstore.limit_definition;
DROP TABLE limitstore.region;
DROP TABLE limitstore.value_type;
DROP SCHEMA limitstore;
