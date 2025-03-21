DROP TABLE IF EXISTS allowance;
DROP TABLE IF EXISTS template;
DROP TABLE IF EXISTS task;
DROP TABLE IF EXISTS template_allowance;
DROP TABLE IF EXISTS task_allowance;

CREATE TABLE allowance (
    uuid CHAR(36) PRIMARY KEY,
    balance DOUBLE,
    username VARCHAR(128) NOT NULL, 
    user_index VARCHAR(128) NOT NULL,
    slug VARCHAR(128) NOT NULL,
    slug_index VARCHAR(128) NOT NULL, 
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    is_archived BOOLEAN NOT NULL,
    is_active BOOLEAN NOT NULL, 
    is_calculated BOOLEAN NOT NULL
);
CREATE UNIQUE iNDEX idx_user_index ON allowance (user_index);
CREATE UNIQUE iNDEX idx_allowance_slug_index ON allowance (slug_index);

CREATE TABLE template (
    uuid CHAR(36) PRIMARY KEY,
    name VARCHAR(64),
    description VARCHAR(255),
    cadence VARCHAR(32),
    category VARCHAR(32),
    slug CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    is_archived BOOLEAN NOT NULL
);
CREATE UNIQUE iNDEX idx_template_slug_index ON template (slug);

CREATE TABLE task (
    uuid CHAR(36) PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    is_complete BOOLEAN NOT NULL,
    is_satisfactory BOOLEAN NOT NULL,
    is_proactive BOOLEAN NOT NULL,
    slug CHAR(36) NOT NULL,
    is_archived BOOLEAN NOT NULL
);
CREATE UNIQUE iNDEX idx_task_slug_index ON task (slug);

CREATE TABLE template_allowance (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    template_uuid CHAR(36) NOT NULL,
    allowance_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    CONSTRAINT fk_template_allowance_uuid FOREIGN KEY (template_uuid) REFERENCES template (uuid),
    CONSTRAINT fk_allowance_template_uuid FOREIGN KEY (allowance_uuid) REFERENCES allowance (uuid)
);
CREATE INDEX idx_allowance_template_xref ON template_allowance (allowance_uuid);
CREATE INDEX idx_template_allowance_xref ON template_allownace (template_uuid);

CREATE TABLE task_allowance (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    task_uuid CHAR(36) NOT NULL,
    allowance_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    CONSTRAINT fk_task_allowance_uuid FOREIGN KEY (task_uuid) REFERENCES task (uuid),
    CONSTRAINT fk_allowance_task_uuid FOREIGN KEY (allowance_uuid) REFERENCES allowance (uuid)
);
CREATE INDEX idx_allowance_task_xref ON task_allowance (allowance_uuid);
CREATE INDEX idx_task_allowance_xref ON task_allowance (task_uuid);

CREATE TABLE template_task (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    template_uuid CHAR(36) NOT NULL,
    task_uuid CHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT UTC_TIMESTAMP,
    CONSTRAINT fk_template_task_uuid FOREIGN KEY (template_uuid) REFERENCES template (uuid),
    CONSTRAINT fk_task_template_uuid FOREIGN KEY (task_uuid) REFERENCES task (uuid)
);
CREATE INDEX idx_task_template_xref ON template_task (task_uuid);
CREATE INDEX idx_template_task_xref ON template_task(template_uuid);

-- service token
CREATE TABLE servicetoken (
    uuid CHAR(36) PRIMARY KEY,
    service_name VARCHAR(32) NOT NULL,
    service_token VARCHAR(2048) NOT NULL,
    service_expires TIMESTAMP NOT NULL,
    refresh_token VARCHAR(128) NOT NULL,
    refresh_expires TIMESTAMP NOT NULL
);
CREATE INDEX idx_servicetoken_servicename ON servicetoken(service_name);
CREATE INDEX idx_servicetoken_refreshexpires ON servicetoken(refresh_expires);