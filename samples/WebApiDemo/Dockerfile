# PostQuantum.Jwt WebApiDemo
#
# IMPORTANT: the native ML-KEM / ML-DSA primitives require OpenSSL 3.5+. NO
# current .NET base image ships it — Debian/Ubuntu images are on OpenSSL 3.0 and
# even Azure Linux 3.0 is only on 3.3.5, both of which make MLDsa.IsSupported
# false so every token op fails closed. We bring OpenSSL 3.5 in ourselves via
# conda-forge and point the runtime loader at it (same approach as the playground
# Dockerfile and the repo's CI).
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

# ---- OpenSSL 3.5 (the base image's 3.3.5 is too old for ML-DSA/ML-KEM) ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS openssl
# gawk: the miniforge installer needs awk, which the Azure Linux image omits.
RUN tdnf install -y gawk && tdnf clean all && \
    curl -fsSL https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh -o /tmp/mf.sh && \
    bash /tmp/mf.sh -b -p /opt/conda && rm -f /tmp/mf.sh && \
    /opt/conda/bin/conda create -y -n pq -c conda-forge "openssl>=3.5" && \
    /opt/conda/bin/conda clean -afy

# ---- runtime ----
FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0 AS runtime
COPY --from=openssl /opt/conda/envs/pq /opt/conda/envs/pq
ENV LD_LIBRARY_PATH=/opt/conda/envs/pq/lib
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "PostQuantum.Jwt.WebApiDemo.dll"]
