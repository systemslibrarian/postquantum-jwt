# PostQuantum.Jwt WebApiDemo
#
# IMPORTANT: the native ML-KEM / ML-DSA primitives require OpenSSL 3.5+.
# The default Debian-based aspnet images ship an older OpenSSL, where the PQ
# paths fail closed. We use the Azure Linux (Mariner) 10 images, which provide
# a new-enough OpenSSL. Confirm with `openssl version` inside the container if
# you swap the base image.
#
# Build context is the REPO ROOT (we reference ../../src). Build with:
#   docker build -f samples/WebApiDemo/Dockerfile -t pqjwt-webapidemo .
#   docker run --rm -p 5080:8080 pqjwt-webapidemo

# ---- build ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS build
WORKDIR /src

# Copy only what the demo needs to build (core lib + aspnetcore + this sample).
COPY src/PostQuantum.Jwt/ src/PostQuantum.Jwt/
COPY src/PostQuantum.Jwt.AspNetCore/ src/PostQuantum.Jwt.AspNetCore/
COPY Directory.Build.props ./
COPY samples/WebApiDemo/ samples/WebApiDemo/

RUN dotnet restore samples/WebApiDemo/WebApiDemo.csproj
RUN dotnet publish samples/WebApiDemo/WebApiDemo.csproj -c Release -o /app --no-restore

# ---- runtime ----
FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0 AS runtime
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "PostQuantum.Jwt.WebApiDemo.dll"]
