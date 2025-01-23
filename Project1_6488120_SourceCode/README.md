# File Sharing Service
#### Suphavadee Cheng, ID: 6488120

## Overview

This is a file-sharing service implemented in Go. Users can securely upload, download, and manage files. The service includes features such as user authentication, file expiration, and access control.

## Features

- User Registration and Login
- File Upload and Download
- File List with User Information
- File Deletion
- Session Management via Cookies
- File Expiration Handling
- Supported File Types: .jpg, .jpeg, .png, .gif, .pdf, .txt, .doc, .docx, .xlsx

## Technology Stack

- **Go**: Programming language
- **PostgreSQL**: Database for storing user and file information
- **Docker**: To run PostgreSQL in a containerized environment

## Prerequisites

- [Go](https://golang.org/dl/) installed
- [Docker](https://www.docker.com/products/docker-desktop) installed

## Getting Started

### Step 1: Set Up the PostgreSQL Database

1. Pull the PostgreSQL Docker image:

   ```bash
   docker pull postgres
2. Run the PostgreSQL container:

   ```bash
   sudo docker run --name pg-container -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=gopgtest -p 5432:5432 -d postgres
- Note: If the container already exists and is stopped, you can restart it using:
   ```bash
   sudo docker start pg-container
- After starting the container, check its status with:
   ```bash
   sudo docker ps -a
3. Access the PostgreSQL database:

   ```bash
   sudo docker exec -it pg-container psql -U postgres -d gopgtest
   gopgtest=# SELECT * FROM files;
   gopgtest=# SELECT * from users;
### Step 2: Update Database Connection (Option)

- Ensure the database connection string in main.go matches your Docker setup:
   ```bash
   connStr := "host=localhost user=postgres password=secret dbname=gopgtest port=5432 sslmode=disable"

### Step 3: Run the Go Application
- In the project directory, run:

    ```bash
    go run main.go
Access the application in web browser at http://localhost:8000.