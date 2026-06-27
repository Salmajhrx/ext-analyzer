FROM node:18-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Install box-js CLI globally
RUN npm install -g box-js

# Set up API server with its own package.json
WORKDIR /opt/api

COPY package.json ./
RUN npm install

COPY api-server.js ./server.js

RUN mkdir -p /samples /results

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

CMD ["node", "server.js"]
