# PqJwtPlayground (Blazor Server)
#
# ML-KEM / ML-DSA require OpenSSL 3.5+. NO current .NET base image ships it:
# the Debian/Ubuntu images are on OpenSSL 3.0, and even Azure Linux 3.0 is only
# on 3.3.5 — both make MLDsa.IsSupported == false, so every token op fails closed
# (HTTP 500). So we bring OpenSSL 3.5 in ourselves via conda-forge (built in an
# SDK stage that has the needed tools) and point the runtime's dynamic loader at
# it (LD_LIBRARY_PATH) — the same approach the repo's CI uses.
# Build from the REPOSITORY ROOT:
#   docker build -f samples/PqJwtPlayground/Dockerfile -t pqjwt-playground .
#   docker run --rm -p 5100:8080 pqjwt-playground

FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS build
WORKDIR /src
COPY src/PostQuantum.Jwt/ src/PostQuantum.Jwt/
COPY Directory.Build.props ./
COPY samples/Shared/ samples/Shared/
COPY samples/PqJwtPlayground/ samples/PqJwtPlayground/
RUN dotnet restore samples/PqJwtPlayground/PqJwtPlayground.csproj
RUN dotnet publish samples/PqJwtPlayground/PqJwtPlayground.csproj -c Release -o /app --no-restore

# OpenSSL 3.5+ via conda-forge. Done in the SDK image because it has curl + tar +
# bash (the slim runtime image lacks tar, which the miniforge installer needs).
FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS openssl
# gawk: the miniforge installer needs awk, which the Azure Linux image omits.
RUN tdnf install -y gawk && tdnf clean all && \
    curl -fsSL https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh -o /tmp/mf.sh && \
    bash /tmp/mf.sh -b -p /opt/conda && rm -f /tmp/mf.sh && \
    /opt/conda/bin/conda create -y -n pq -c conda-forge "openssl>=3.5" && \
    /opt/conda/bin/conda clean -afy

FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0 AS runtime
# Bring the OpenSSL 3.5 env (same path preserved so library RPATHs resolve) and
# put it first on the loader path so .NET's libcrypto/libssl resolve to 3.5+.
COPY --from=openssl /opt/conda/envs/pq /opt/conda/envs/pq
ENV LD_LIBRARY_PATH=/opt/conda/envs/pq/lib
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "PostQuantum.Jwt.Playground.dll"]
