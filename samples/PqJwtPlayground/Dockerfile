# PqJwtPlayground (Blazor Server)
#
# OpenSSL 3.5+ required for ML-KEM / ML-DSA. Use the Azure Linux 3.0 images;
# the default Ubuntu 24.04 .NET 10 images ship OpenSSL 3.0 and fail closed on
# the PQ paths. Build from the REPOSITORY ROOT:
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

FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0 AS runtime
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "PostQuantum.Jwt.Playground.dll"]
