FROM ubuntu:22.04

# Install some packages
RUN apt-get update && apt-get install -y python3 python3-pip

# Copy application files
COPY . /app
WORKDIR /app

# Install dependencies
RUN pip3 install -r requirements.txt

# Running as root user - this is a security vulnerability!
USER root

# Expose port
EXPOSE 8080

# Run the application
CMD ["python3", "main.py"]
