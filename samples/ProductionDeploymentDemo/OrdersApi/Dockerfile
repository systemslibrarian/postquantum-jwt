# PostQuantum.Jwt ProductionDeploymentDemo — OrdersApi
#
# IMPORTANT: native ML-KEM / ML-DSA support requires OpenSSL 3.5+ on Linux.
# The current .NET base images do not provide that yet, so this sample follows
# the same conda-forge OpenSSL approach used elsewhere in the repository.

# ---- build ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS build
WORKDIR /src

COPY Directory.Build.props ./
COPY src/PostQuantum.Jwt/ src/PostQuantum.Jwt/
COPY src/PostQuantum.Jwt.AspNetCore/ src/PostQuantum.Jwt.AspNetCore/
COPY samples/ProductionDeploymentDemo/ samples/ProductionDeploymentDemo/

RUN dotnet restore samples/ProductionDeploymentDemo/OrdersApi/OrdersApi.csproj
RUN dotnet publish samples/ProductionDeploymentDemo/OrdersApi/OrdersApi.csproj -c Release -o /app --no-restore

# ---- OpenSSL 3.5 ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS openssl
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
ENTRYPOINT ["dotnet", "PostQuantum.Jwt.ProductionDeploymentDemo.OrdersApi.dll"]
