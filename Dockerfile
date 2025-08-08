# Dockerfile
# This file contains the instructions to build your application's container image.

# Use an official, slim Python runtime as a parent image for a smaller footprint.
FROM python:3.11-slim

# Set the working directory inside the container. All subsequent commands will run from here.
WORKDIR /app

# Install system dependencies required by your Python libraries.
# - libmagic1 is for python-magic (file type identification).
# - yara is for yara-python (malware pattern matching).
# - python3-tk is for tkinter (the GUI toolkit).
# We chain commands to reduce image layers and clean up the apt cache to keep the image small.
RUN apt-get update && apt-get install -y \
    libmagic1 \
    yara \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements file first to leverage Docker's layer caching.
# The layer will only be rebuilt if requirements.txt changes.
COPY requirements.txt .

# Install Python packages using pip.
# --no-cache-dir reduces the image size by not storing the pip cache.
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the necessary application source code into the container.
# This prevents secrets and unnecessary files (as defined in .dockerignore) from being included.
COPY gui_main.py .
COPY main.py .
COPY analyzers/ ./analyzers/
COPY utils/ ./utils/
COPY rules/ ./rules/

# The command that will be executed when the container starts.
# This launches your GUI application.
CMD ["python3", "gui_main.py"]
