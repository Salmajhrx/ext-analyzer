# node:20-bullseye (not slim) — includes glibc which isolated-vm requires.
# Alpine/musl will fail to compile isolated-vm's native C++ bindings.
FROM node:22-bookworm

# Build tools required by isolated-vm (native C++ addon via node-gyp)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        #python3-is-python \
        make \
        g++ \
        curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/api

COPY package.json ./

# isolated-vm on Node 20 requires --no-node-snapshot at runtime.
# npm_config_build_from_source forces a clean native compile inside the container
# so we don't accidentally pull a pre-built binary for the wrong architecture.
ENV npm_config_build_from_source=true
RUN npm install

COPY api-server.js ./server.js

RUN mkdir -p /samples /results /tmp/uploads

EXPOSE 8081

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -sf http://localhost:8081/health || exit 1

# --no-node-snapshot is required for isolated-vm on Node 20+
CMD ["node", "--no-node-snapshot", "server.js"]