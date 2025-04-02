FROM node:18-alpine

WORKDIR /app

# Add build arguments
ARG REACT_APP_API_URL
ARG REACT_APP_DETECTION_URL
ARG REACT_APP_IPLOOKUP_URL

# Set environment variables
ENV REACT_APP_API_URL=${REACT_APP_API_URL}
ENV REACT_APP_DETECTION_URL=${REACT_APP_DETECTION_URL}
ENV REACT_APP_IPLOOKUP_URL=${REACT_APP_IPLOOKUP_URL}

# Configure npm to use a different registry and disable strict SSL
RUN npm config set registry https://registry.npmjs.org/ && \
    npm config set strict-ssl false

# Install dependencies
COPY package*.json ./
RUN npm install --legacy-peer-deps && \
    npm install ajv@8.12.0 ajv-keywords@5.1.0 --legacy-peer-deps

# Copy application code
COPY . .

# Build the application
RUN npm run build

# Install serve package
RUN npm install -g serve

# Expose port
EXPOSE 3000

# Start the application with serve
CMD ["serve", "-s", "build", "-l", "3000"]