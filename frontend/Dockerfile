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

# Install dependencies
COPY package*.json ./
RUN npm install

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