# Cookie Confusion Toolkit Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Chrome/Chromium dependencies
    wget \
    gnupg \
    unzip \
    # Firefox dependencies
    firefox-esr \
    # General utilities
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Chrome
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Install ChromeDriver
RUN CHROME_VERSION=$(google-chrome --version | awk '{print $3}' | awk -F. '{print $1}') \
    && wget -O /tmp/chromedriver.zip "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROME_VERSION/chromedriver_linux64.zip" \
    && unzip /tmp/chromedriver.zip -d /usr/local/bin/ \
    && rm /tmp/chromedriver.zip \
    && chmod +x /usr/local/bin/chromedriver

# Install GeckoDriver for Firefox
RUN GECKODRIVER_VERSION=$(curl -s https://api.github.com/repos/mozilla/geckodriver/releases/latest | grep tag_name | cut -d '"' -f 4) \
    && wget -O /tmp/geckodriver.tar.gz "https://github.com/mozilla/geckodriver/releases/download/$GECKODRIVER_VERSION/geckodriver-$GECKODRIVER_VERSION-linux64.tar.gz" \
    && tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin/ \
    && rm /tmp/geckodriver.tar.gz \
    && chmod +x /usr/local/bin/geckodriver

# Set up working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the toolkit source code
COPY src/ ./src/
COPY setup.py .
COPY README.md .
COPY LICENSE .

# Install the toolkit
RUN pip install -e .

# Create directories for results and logs
RUN mkdir -p /app/results /app/logs

# Set up environment variables
ENV PYTHONPATH=/app
ENV DISPLAY=:99

# Install Xvfb for headless browser testing
RUN apt-get update && apt-get install -y xvfb && rm -rf /var/lib/apt/lists/*

# Create a script to start Xvfb and run the toolkit
RUN echo '#!/bin/bash\n\
Xvfb :99 -screen 0 1920x1080x24 &\n\
exec "$@"' > /entrypoint.sh \
    && chmod +x /entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["python", "-m", "src.cli", "--help"]

# Add labels for container metadata
LABEL maintainer="geeknik <your.email@example.com>"
LABEL version="0.1.0"
LABEL description="Cookie Confusion Toolkit - A tool for testing cookie parsing inconsistencies"
LABEL repository="https://github.com/geeknik/cookie-confusion-toolkit"
