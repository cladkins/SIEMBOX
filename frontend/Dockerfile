FROM node:18-alpine

WORKDIR /app

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