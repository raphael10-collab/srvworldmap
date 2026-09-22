#include "MapCommandService.h"

#include "SessionService.h"

#include <drogon/drogon.h>
#include <json/json.h>

#include <cmath>
#include <cstdint>
#include <memory>
#include <string>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <crypt.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

/*
  It accepts marker commands over NATS
  It derives the owner from the supplied authenticated session token
  It validates coordinates
  I inserts into the existing restricted_features table
*/

namespace
{
    constexpr double kMinLongitude = -180.0;
    constexpr double kMaxLongitude = 180.0;
    constexpr double kMinLatitude = -90.0;
    constexpr double kMaxLatitude = 90.0;

    bool validCoordinate(double longitude, double latitude)
    {
        return std::isfinite(longitude) &&
           std::isfinite(latitude) &&
           longitude >= kMinLongitude &&
           longitude <= kMaxLongitude &&
           latitude >= kMinLatitude &&
           latitude <= kMaxLatitude;
    }

    void logCommandError(const std::string& message)
    {
        LOG_ERROR << "MapCommandService: " << message;
    }


    std::string sha256Hex(const std::string& value)
    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLength = 0;

        EVP_MD_CTX* context = EVP_MD_CTX_new();

        if (context == nullptr)
        {
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }

        if (EVP_DigestInit_ex(
                context,
                EVP_sha256(),
                nullptr) != 1 ||
            EVP_DigestUpdate(
                context,
                value.data(),
                value.size()) != 1 ||
            EVP_DigestFinal_ex(
                context,
                digest,
                &digestLength) != 1)
        {
            EVP_MD_CTX_free(context);

            throw std::runtime_error("SHA-256 calculation failed");
        }

        EVP_MD_CTX_free(context);

        std::ostringstream output;

        output << std::hex
               << std::setfill('0');

        for (unsigned int i = 0; i < digestLength; ++i)
        {
            output << std::setw(2) << static_cast<unsigned int>(digest[i]);
        }

        return output.str();
    }


    std::string generateRawToken()
    {
        // 32 random bytes = 256 bits of entropy.
        unsigned char randomBytes[32];

        if (RAND_bytes(randomBytes, sizeof(randomBytes)) != 1)
        {
            throw std::runtime_error("Secure random token generation failed");
        }

        std::ostringstream output;

        output << std::hex << std::setfill('0');

        for (unsigned char byte : randomBytes)
        {
            output << std::setw(2) << static_cast<unsigned int>(byte);
        }
        return output.str();
    }

} // namespace

void MapCommandService::initAndStart(const Json::Value& /*config*/)
{
    LOG_INFO << "MapCommandService started";
}

void MapCommandService::shutdown()
{
    LOG_INFO << "MapCommandService stopped";
}

void MapCommandService::handle(const std::string& subject, const std::string& payload)
{

    /*

        The intended flow is:

        Client
          │
          │  email + plaintext password inside mutual-TLS connection
          ▼
        NATS server
          │
          │  forwards authenticated request
          ▼
        WorldMapAPI
          │
          │  bcrypt verifies password against password_hash
          ▼
        Database

    */

    LOG_INFO << "Received authentication request";

    // Ignore unrelated NATS subjects.
    if (subject != "map.marker.create")
    {
        return;
    }

    Json::CharReaderBuilder readerBuilder;
    Json::Value command;
    std::string parseErrors;

    const auto reader = std::unique_ptr<Json::CharReader>(readerBuilder.newCharReader());

    const char* begin = payload.data();
    const char* end = begin + payload.size();

    if (!reader->parse(begin, end, &command, &parseErrors))
    {
        logCommandError("invalid JSON payload: " + parseErrors);
        return;
    }

    /*
     * Expected command:
     *
     * {
     *   "session_token": "...",
     *   "longitude": 9.1538064,
     *   "latitude": 45.4565458,
     *   "title": "Example marker",
     *   "description": "Restricted marker"
     * }
     *
     * user_id is deliberately not read from the payload.
     */
    if (!command.isMember("session_token") ||
        !command["session_token"].isString() ||
        !command.isMember("longitude") ||
        !command["longitude"].isNumeric() ||
        !command.isMember("latitude") ||
        !command["latitude"].isNumeric())
    {
        logCommandError("missing or invalid required fields");
        return;
    }

    const std::string sessionToken = command["session_token"].asString();

    if (sessionToken.empty())
    {
        logCommandError("empty session token");
        return;
    }

    const double longitude = command["longitude"].asDouble();

    const double latitude =command["latitude"].asDouble();

    if (!validCoordinate(longitude, latitude))
    {
        logCommandError("coordinates outside valid bounds");
        return;
    }

    const std::string title = command.get("title", "").asString();

    const std::string description = command.get("description", "").asString();

    /*
     * SessionService performs the token hash lookup and checks:
     * - token validity
     * - expiration
     * - revocation
     * - user existence
     */
    SessionService::validateAsync(
        sessionToken,
        [longitude,
         latitude,
         title,
         description](std::optional<AuthenticatedUser> user) {
            if (!user.has_value())
            {
                logCommandError("unauthorized marker command");
                return;
            }

            if (!user->canViewRestrictedMap)
            {
                logCommandError("user lacks restricted-map permission");
                return;
            }

            auto dbClient = drogon::app().getDbClient("securetiles");

            if (!dbClient)
            {
                logCommandError("database client is unavailable");
                return;
            }

            LOG_INFO
                << "Authenticated user id=" << user->id
                << ", canViewRestrictedMap="
                << (user->canViewRestrictedMap ? "true" : "false");

            /*
             * The owner ID comes exclusively from the validated session.
             */

            static const std::string sql = R"SQL(
                INSERT INTO restricted_features
                    (id, owner_user_id, geom, name, properties)
                VALUES
                    (
                        nextval('restricted_features_id_seq'),
                        $1::bigint,
                        ST_SetSRID(
                            ST_MakePoint($2::double precision, $3::double precision),
                            4326
                        ),
                        $4::text,
                        jsonb_build_object(
                            'description', $5::text,
                            'source', 'map-command'::text
                        )
                    )
            )SQL";

            dbClient->execSqlAsync(
                sql,
                [userId = user->id](
                    const drogon::orm::Result& result) {
                    LOG_INFO
                        << "Created restricted map feature for user "
                        << userId;
                },
                [](const drogon::orm::DrogonDbException& exception) {
                    logCommandError("feature insertion failed: " + std::string(exception.base().what()));
                },
                user->id,
                longitude,
                latitude,
                title,
                description);
        });
}


bool MapCommandService::authenticateUser(const std::string& email, const std::string& password)
{
    // Query the database.
    // Compare the supplied password with the stored password hash.
    // Never compare or store plaintext passwords.

    if (email.empty() || password.empty())
    {
        return false;
    }

    try
    {
        auto dbClient = drogon::app().getDbClient("securetiles");

        const auto result = dbClient->execSqlSync(
            R"SQL(
                SELECT password_hash, can_view_restricted_map
                FROM users
                WHERE lower(email) = lower($1)
                LIMIT 1
            )SQL",
            email);

        if (result.empty())
        {
            // Do not reveal whether the username exists.
            return false;
        }

        const std::string storedHash = result[0]["password_hash"].as<std::string>();

        const bool allowed = result[0]["can_view_restricted_map"].as<bool>();

        if (!allowed || storedHash.empty())
        {
            return false;
        }

        /*
         * crypt() uses the algorithm encoded in storedHash.
         * Therefore a bcrypt hash beginning with $2b$ causes
         * bcrypt verification.
         *
         * The returned value is compared with the stored hash.
         */
        char* calculatedHash = crypt(password.c_str(), storedHash.c_str());

        if (calculatedHash == nullptr)
        {
            LOG_ERROR << "Password hash verification failed for user " << email;

            return false;
        }

        /*
         * The result of crypt() must be compared in constant time.
         */
        if (std::strlen(calculatedHash) != storedHash.size())
        {
            return false;
        }

        unsigned char difference = 0;

        for (std::size_t i = 0; i < storedHash.size(); ++i)
        {
            difference |= static_cast<unsigned char>(calculatedHash[i] ^ storedHash[i]);
        }

        return difference == 0;
    }
    catch (const std::exception& exception)
    {
        LOG_ERROR << "Database error during authentication: " << exception.what();

        return false;
    }
}

std::string MapCommandService::createSessionForUser(const std::string& email)
{
    // Generate a cryptographically secure random token.
    // Store only a hash of the token in the database.
    // Return the raw token once in the response.

    if (email.empty())
    {
        throw std::invalid_argument("Email cannot be empty");
    }

    const std::string rawToken = generateRawToken();
    const std::string tokenHash = sha256Hex(rawToken);

    try
    {
        auto dbClient = drogon::app().getDbClient("securetiles");

        /*
         * Look up the user ID and insert the token hash.
         *
         * The raw token is never inserted into the database.
         */

        const auto result = dbClient->execSqlSync(
            R"SQL(
                INSERT INTO sessions
                (
                    user_id,
                    session_id_hash,
                    expires_at
                )
                SELECT
                    id,
                    decode($2, 'hex'),
                    CURRENT_TIMESTAMP + INTERVAL '288 hours'
                FROM users
                WHERE lower(email) = lower($1)
                RETURNING user_id
            )SQL",
            email,
            tokenHash);

        if (result.empty())
        {
            throw std::runtime_error("Could not create session for user");
        }

        /*
         * Return the raw token exactly once.
         * The database contains only tokenHash.
         */
        return rawToken;
    }
    catch (const std::exception& exception)
    {
        LOG_ERROR
            << "Could not create session for user "
            << email
            << ": "
            << exception.what();

        throw;
    }
}

