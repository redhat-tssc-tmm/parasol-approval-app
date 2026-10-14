# Stage 1: Build React frontend
FROM registry.access.redhat.com/ubi9/nodejs-20:latest AS frontend-build
USER 0
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --legacy-peer-deps
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Go backend
FROM registry.access.redhat.com/ubi9/go-toolset:1.22 AS backend-build
USER 0
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY internal/ ./internal/
# Embed the built frontend
COPY --from=frontend-build /app/frontend/dist ./frontend/dist
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o parasol-approval-process .

# Stage 3: Runtime
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
RUN microdnf install -y shadow-utils && microdnf clean all
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser
WORKDIR /app
COPY --from=backend-build /app/parasol-approval-process .
RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 8080
ENTRYPOINT ["./parasol-approval-process"]
