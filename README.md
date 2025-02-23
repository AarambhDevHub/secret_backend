# Secure Secret Management System - Backend

[![Watch the video](https://img.youtube.com/vi/fUBgSMgCRVI/maxresdefault.jpg)](https://youtu.be/fUBgSMgCRVI)

This project is the backend of the **Secure Secret Management System** built with **Rust** using the **Axum** framework. It provides a secure API for managing secrets with user-specific and central databases, multiple encryption methods, versioning, and access control using API keys.

## Features

- **User-Specific Database**: Manage secrets unique to each user.
- **Central Database**: Access a centralized storage for all secrets.
- **Encryption Methods**: Four types of encryption to ensure data security.
- **Versioning**: Maintain multiple versions of secrets for easier management.
- **API Key Access**: Secure access to the API for managing secrets.

## Getting Started

### Prerequisites

- Rust (latest stable version)
- Cargo (comes with Rust)
- PostgreSQL (for database management)

### Installation

1. Set up your environment variables:
    
    Create a .env file with the following content:
    ```
    # ----------------------------------------------------------------------------- 
    # Database (PostgreSQL) 
    # ----------------------------------------------------------------------------- 
    DATABASE_URL=postgresql://postgres:password@localhost:5432/secret_management 

    # ----------------------------------------------------------------------------- 
    # JSON Web Token Credentials 
    # ----------------------------------------------------------------------------- 
    JWT_SECRET_KEY=my_ultra_secure_jwt_secret_key 
    JWT_MAXAGE=60
    ```

2. Install dependencies and build the project:
    
    ```
    cargo build
    ```

3. Run the application:

    ```
    cargo run
    ```

The API will be available at http://localhost:8000.

## Support Us
If you find this project helpful, consider supporting us through donations: [Buy Me a Coffee](https://buymeacoffee.com/aarambhdevhub).
