#include "TileService.h"
#include <cmath>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

static int hexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static std::string decodeHex(const std::string& input)
{
    if (input.empty())
    {
        return {};
    }

    if (input.size() % 2 != 0)
    {
        throw std::runtime_error("Invalid hexadecimal tile data");
    }

    std::string output;
    output.reserve(input.size() / 2);

    for (std::size_t i = 0; i < input.size(); i += 2)
    {
        const int high = hexValue(input[i]);
        const int low = hexValue(input[i + 1]);

        if (high < 0 || low < 0)
        {
            throw std::runtime_error("Invalid hexadecimal tile data");
        }

        output.push_back(static_cast<char>((high << 4) | low));
    }

    return output;
}


static std::string decodeBase64(const std::string& input)
{
    if (input.empty())
    {
        return {};
    }

    std::vector<unsigned char> output((input.size() * 3) / 4 + 3);

    int length = EVP_DecodeBlock(output.data(), reinterpret_cast<const unsigned char*>(input.data()), static_cast<int>(input.size()));

    if (length < 0)
    {
        throw std::runtime_error("Invalid Base64 tile data");
    }

    int padding = 0;

    if (!input.empty() && input.back() == '=')
    {
        padding++;
    }

    if (input.size() > 1 && input[input.size() - 2] == '=')
    {
        padding++;
    }

    length -= padding;

    return std::string(reinterpret_cast<char*>(output.data()), static_cast<std::size_t>(length));
}

/*
 * The vector tile endpoint should explicitly return raw binary data,
 * and the server should verify that the response begins with a valid MVT payload rather than a textual PostgreSQL representation.

 * Use ST_Transform directly in the tile query.
 * This avoids relying on the trigger-populated geom_3857 column and makes the query self-contained.
*/

bool TileService::validTileCoordinate(int z, int x, int y)
{
    if (z < 0 || z > 22) {
        return false;
    }

    const int limit = 1 << z;

    return x >= 0 &&
           x < limit &&
           y >= 0 &&
           y < limit;
}

void TileService::getRestrictedTile(std::int64_t userId, int z, int x, int y, TileCallback&& callback)
{
    auto callbackHolder = std::make_shared<TileCallback>(std::move(callback));

    if (userId <= 0) {
        (*callbackHolder)(false, {}, "Invalid authenticated user");
        return;
    }

    if (!validTileCoordinate(z, x, y))
    {
        (*callbackHolder)(false, {}, "Invalid tile coordinate");
        return;
    }

    auto db = drogon::app().getDbClient("securetiles");

    if (!db)
    {
        (*callbackHolder)(false, {}, "Database is unavailable");
        return;
    }

    static const std::string sql = R"SQL(
        WITH tile AS (
            SELECT ST_TileEnvelope($2, $3, $4) AS bounds
        ),
        features AS (
            SELECT
                rf.id,
                rf.name,
                rf.properties,
                ST_AsMVTGeom(
                    rf.geom_3857,
                    tile.bounds,
                    4096,
                    64,
                    true
                ) AS geom
            FROM public.restricted_features AS rf
            CROSS JOIN tile
            WHERE rf.owner_user_id = $1
              AND rf.geom_3857 && tile.bounds
        )
        SELECT encode(
            COALESCE(
                ST_AsMVT(features, 'restricted', 4096, 'geom'),
                ''::bytea
            ),
            'hex'
        ) AS tile
        FROM features;
    )SQL";

    db->execSqlAsync(
        sql,

        [callbackHolder](const drogon::orm::Result& result)
        {
            if (result.empty())
            {
                (*callbackHolder)(false, {}, "Tile query returned no result");
                return;
            }

            const auto& field = result[0]["tile"];

            if (field.isNull())
            {
                (*callbackHolder)(true, {}, {});
                return;
            }

            try
            {
                const std::string encodedTile = field.as<std::string>();
                std::string tileData = decodeHex(encodedTile);
                LOG_INFO << "MVT tile size: " << tileData.size();
                (*callbackHolder)(true, std::move(tileData), {});
            }
            catch (const std::exception& error)
            {
                LOG_ERROR << "Could not decode MVT hex: " << error.what();
                (*callbackHolder)(false, {}, "Invalid encoded tile data");
            }

        },

        [callbackHolder](const drogon::orm::DrogonDbException& error)
        {
            LOG_ERROR << "Tile query failed: " << error.base().what();

            (*callbackHolder)(false, {}, "Tile query failed");
        },

        userId,
        z,
        x,
        y);
}
