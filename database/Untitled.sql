USE nexa_db;

ALTER TABLE messages
ADD COLUMN attachment_url VARCHAR(500) NULL,
ADD COLUMN attachment_type VARCHAR(30) NULL,
ADD COLUMN attachment_name VARCHAR(255) NULL;