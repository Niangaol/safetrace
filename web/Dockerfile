# 前端镜像：两阶段构建（Node 构建 → nginx 托管静态产物）

FROM node:22-alpine AS build
WORKDIR /app

# 可选 npm registry 覆盖。
# 为什么需要：实测在某些网络环境（本机在境内）容器**连不上 registry.npmjs.org**
# （`npm error network ... behind a proxy`，重试 782s 后失败），而镜像源
# registry.npmmirror.com 可达。**不写死默认值**：能直连的环境用它反而更慢，
# 所以留空表示用官方源，需要时由 compose 的 build args 传入。
ARG NPM_REGISTRY=""

COPY package*.json ./
RUN if [ -n "$NPM_REGISTRY" ]; then \
      npm config set registry "$NPM_REGISTRY" && echo "使用 npm registry: $NPM_REGISTRY"; \
    else \
      echo "使用默认 npm registry"; \
    fi \
 && npm install

COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
