# Use Alpine Linux as the base image
FROM python:3.9-alpine

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apk update \
    && apk add --virtual build-deps gcc python3-dev musl-dev \
    && apk add --no-cache \
        build-base \
        mariadb-connector-c-dev \
        libffi-dev \
        openssl-dev \
        redis \
        mariadb-dev

# Copy the project files to the working directory
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the environment variables
ENV FLASK_APP=auth.py

# Expose the API port
EXPOSE 5000

# Set the command to run the API server
# CMD ["python", "auth.py"]
# Start the Gunicorn server and redirect logs to stdout
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "auth:app"]
