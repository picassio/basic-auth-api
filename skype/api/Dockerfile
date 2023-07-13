# Use Alpine Linux as the base image
FROM python:3.9-alpine

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apk update

# Copy the project files to the working directory
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the environment variables
ENV FLASK_APP=api.py

# Expose the API port
EXPOSE 5001

# Set the command to run the API server
# CMD ["python", "auth.py"]
# Start the Gunicorn server and redirect logs to stdout
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--access-logfile", "-", "--error-logfile", "-", "api:app"]
