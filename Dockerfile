# Use the official Go image as the build base
FROM golang:1.23-alpine AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the go.mod and go.sum files to the working directory
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code to the working directory
COPY . .

# Build the Go application binary
RUN go build -o ldap-portal

# Use a minimal base image to run the application
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the binary from the build stage to the current stage
COPY --from=build /app/ldap-portal .
COPY --from=build /app/data .

# Expose the port on which the application will run
EXPOSE 8972

# Command to run the application
CMD ["./ldap-portal"]
