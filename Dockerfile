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
ARG CHROME_DRIVER_VERSION=119.0.6045.105
RUN wget -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/${CHROME_DRIVER_VERSION}/chromedriver_linux64.zip \
    && unzip /tmp/chromedriver.zip -d /usr/local/bin/ \
    && rm /tmp/chromedriver.zip \
    && chmod +x /usr/local/bin/chromedriver

# Install geckodriver for Firefox
ARG GECKO_DRIVER_VERSION=0.33.0
RUN wget -O /tmp/geckodriver.tar.gz https://github.com/mozilla/geckodriver/releases/download/v${GECKO_DRIVER_VERSION}/geckodriver-v${GECKO_DRIVER_VERSION}-linux64.tar.gz \
    && tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin/ \
    && rm /tmp/geckodriver.tar.gz \
    && chmod +x /usr/local/bin/geckodriver

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the toolkit code
COPY . .

# Make the entry point script executable
RUN chmod +x cct

# Set up environment
ENV PYTHONPATH="/app:/app/src"
ENV DISPLAY=:99

# Install Xvfb for headless browser support
RUN apt-get update && apt-get install -y xvfb && rm -rf /var/lib/apt/lists/*

# Create a startup script that launches Xvfb
RUN echo '#!/bin/bash\nXvfb :99 -screen 0 1024x768x24 &\nexec "$@"' > /usr/local/bin/start-xvfb.sh \
    && chmod +x /usr/local/bin/start-xvfb.sh

# Create results directory
RUN mkdir -p /app/results

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/start-xvfb.sh", "./cct"]

# Default command
CMD ["--help"]
