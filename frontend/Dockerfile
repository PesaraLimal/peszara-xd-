FROM node:18-alpine

WORKDIR /app

# Copy dependency configs
COPY package.json ./
RUN npm install

# Copy frontend source files
COPY . .

# Expose Next.js port
EXPOSE 3000

# Run development server to bypass build-time static fetch issues
CMD ["npm", "run", "dev"]
