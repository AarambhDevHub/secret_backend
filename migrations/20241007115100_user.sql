-- Add migration script here
-- Create ENUM type for encryption methods
CREATE TYPE encryption_method AS ENUM ('AES256', 'Chacha20', 'Blowfish', 'DESTripleDES');

-- Enable the UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create the users table
CREATE TABLE users (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    encryption_method encryption_method NULL, -- Now nullable
    keys BYTEA NULL,                          -- Now nullable
    api_keys VARCHAR(255) NULL,               -- Now nullable
    db_connection JSON NULL,                   -- Now nullable
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create an index on the email column for faster lookup
CREATE INDEX users_email_idx ON users (email);
