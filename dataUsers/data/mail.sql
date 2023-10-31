CREATE DATABASE database TEMPLATE template0 ENCODING 'UTF8';


\c database;


CREATE TABLE IF NOT EXISTS register (
    id VARCHAR PRIMARY KEY,
    username VARCHAR(255) COLLATE "en_US.utf8" UNIQUE,
    password VARCHAR(255) COLLATE "en_US.utf8"
);


CREATE INDEX ON register(id);



