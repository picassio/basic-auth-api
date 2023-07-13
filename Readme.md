# API Documentation

This repository contains an API for user management. It provides endpoints for user registration, login, user information retrieval, role management, and more.

## Requirements

- Python 3.9 or later
- Docker
- Docker Compose

## Getting Started

1. Clone the repository:

   ```shell
   git clone https://github.com/yourusername/api.git
   ```

2. Navigate to the project directory:

   ```shell
   cd api/auth
   ```

3. Create a .env file in the project directory and define the required environment variables. You can use the provided .env.example file as a template.  
4. Build and run the API using Docker Compose:

   ```shell
   docker-compose up --build
   ```
This will build the Docker image and start the containers for the API and the MySQL database.
5. To stop the containers, press Ctrl+C in the terminal or run:

   ```shell
   docker-compose down
   ```

## API Documentation
The API documentation is available in Swagger format. You can access it by visiting http://localhost:5000/api/docs in your web browser.

## Development
If you want to run the API without Docker for development purposes, follow these steps:

1. Install the Python dependencies:

   ```shell
   pip install -r requirements.txt
   ```

2. Set the required environment variables in the .env file.

3. Run the Flask development server:

    ```shell
    python auth.py
    ```

The API will be accessible at http://localhost:5000 for testing and development.
