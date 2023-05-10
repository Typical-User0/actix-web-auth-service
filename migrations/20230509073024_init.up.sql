CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE
    "users" (
                id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
                name VARCHAR(100) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                verified BOOLEAN NOT NULL DEFAULT FALSE,
                password VARCHAR(100) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'user',
                otp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                otp_verified BOOLEAN NOT NULL DEFAULT FALSE,
                otp_base32 VARCHAR(400),
                otp_auth_url VARCHAR(400),
                created_at TIMESTAMP
                       WITH
                           TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP
                       WITH
                           TIME ZONE DEFAULT NOW()
);

CREATE INDEX users_email_idx ON users (email);
CREATE INDEX users_uuid_idx ON users (id);