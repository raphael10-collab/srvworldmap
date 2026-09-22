#include <drogon/drogon.h>
#include "plugins/NatsPlugin.h"
#include "controllers/TileController.h"
#include "controllers/AuthController.h"
#include "controllers/MarkerController.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

using json = nlohmann::json;

static std::string readSecretFile(const std::filesystem::path& path)
{
    std::ifstream input(path);

    if (!input) {
        throw std::runtime_error(
            "Unable to open PostgreSQL secret file: " + path.string());
    }

    std::string secret;
    std::getline(input, secret);

    // Remove a possible CR from a Windows-style line ending.
    if (!secret.empty() && secret.back() == '\r') {
        secret.pop_back();
    }

    if (secret.empty()) {
        throw std::runtime_error("PostgreSQL secret is empty");
    }

    return secret;
}

static void writeRuntimeConfig(const std::filesystem::path& outputPath,
                               const std::string& password)
{
    json config = {
        {"listeners", json::array({
            {
                {"address", "127.0.0.1"},
                {"port", 3000}
            }
        })},

        {"db_clients", json::array({
            {
                {"name", "securetiles"},
                {"rdbms", "postgresql"},
                {"host", "127.0.0.1"},
                {"port", 5432},
                {"dbname", "securetiles"},
                {"user", "worldmap_api"},
                {"passwd", password},
                {"number_of_threads", 8},
                {"number_of_connections", 4},
                {"timeout", 5}
            }
        })},

        {"plugins", json::array({
            {
                {"name", "NatsPlugin"},
                {"dependencies", json::array()},
                {"config", {
                    {"server", "tls://10.50.0.2:4222"},
                    {"subject", "map.marker.create"},
                    {"login_subject", "auth.login.request"},
                    {"queue_group", "worldmap-api"}
                }}
            }
        })}
    };

    std::filesystem::create_directories(outputPath.parent_path());

    // Restrict the file before writing it.
    int fd = ::open(outputPath.c_str(),
                    O_WRONLY | O_CREAT | O_TRUNC,
                    S_IRUSR | S_IWUSR);

    if (fd == -1) {
        throw std::runtime_error("Unable to create runtime Drogon config");
    }

    ::close(fd);

    std::ofstream output(outputPath);
    if (!output) {
        throw std::runtime_error("Unable to write runtime Drogon config");
    }

    output << config.dump(2) << '\n';
    output.close();

    // Enforce permissions even if the file already existed.
    if (::chmod(outputPath.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw std::runtime_error("Unable to set runtime config permissions");
    }
}

int main()
{
    try
    {
        const auto password = readSecretFile("/srv/worldmap/postgres-password");

        const auto runtimeConfig = std::filesystem::path("/srv/worldmap/config.json");

        writeRuntimeConfig(runtimeConfig, password);

        drogon::app().loadConfigFile(runtimeConfig.string());
        drogon::app().addListener("127.0.0.1", 3000);
        drogon::app().registerController(std::make_shared<TileController>());

        drogon::app().run();

        // Remove the generated file when Drogon stops.
        std::error_code ec;
        std::filesystem::remove(runtimeConfig, ec);

        return 0;
     }
     catch (const std::exception& ex)
     {
         std::cerr << "Startup failed: " << ex.what() << '\n';
         return 1;
    }
}
