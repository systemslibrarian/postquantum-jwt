# PostQuantum.Jwt RefreshTokenDemo
# OpenSSL 3.5+ required (Azure Linux 3.0 base). Build context = repo root:
#   docker build -f samples/RefreshTokenDemo/Dockerfile -t pqjwt-refresh .

FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS build
WORKDIR /src
COPY src/PostQuantum.Jwt/ src/PostQuantum.Jwt/
COPY src/PostQuantum.Jwt.AspNetCore/ src/PostQuantum.Jwt.AspNetCore/
COPY Directory.Build.props ./
COPY samples/RefreshTokenDemo/ samples/RefreshTokenDemo/
RUN dotnet restore samples/RefreshTokenDemo/RefreshTokenDemo.csproj
RUN dotnet publish samples/RefreshTokenDemo/RefreshTokenDemo.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0 AS runtime
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "PostQuantum.Jwt.RefreshTokenDemo.dll"]
