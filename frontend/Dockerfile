FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Run next build to compile the TypeScript and React code
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start"]
