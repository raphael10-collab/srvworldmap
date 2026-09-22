#include "SessionService.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <unistd.h>
#include <crypt.h>

namespace
{
    constexpr std::size_t kSessionTokenBytes = 32;
    constexpr int kSessionLifetimeSeconds = 288 * 60 * 60;

    bool isSafeSessionToken(const std::string& value)
    {
        /*
         * generateSessionToken() currently returns hexadecimal characters,
         * but accepting URL-safe characters also allows future Base64URL tokens.
        */
        if (value.empty() || value.size() > 256)
        {
            return false;
        }

        return std::all_of(value.begin(), value.end(), [](unsigned char c)
        {
            return std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
        });
    }

    drogon::HttpResponsePtr jsonError(drogon::HttpStatusCode status, const std::string& message)
    {
        Json::Value body;
        body["error"] = message;

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);

        response->setStatusCode(status);
        response->addHeader("Cache-Control", "no-store");

        response->addHeader("X-Content-Type-Options", "nosniff");

        return response;
    }

    drogon::HttpResponsePtr jsonOk()
    {
        Json::Value body;
        body["ok"] = true;

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);

        response->setStatusCode(drogon::k200OK);
        response->addHeader("Cache-Control", "no-store");

        return response;
    }

    std::string getJsonString(const Json::Value& json, const char* key)
    {
        if (!json.isObject() || !json.isMember(key) || !json[key].isString())
        {
            return {};
        }
        return json[key].asString();
    }

    /*
     * This example verifies bcrypt-compatible hashes through crypt_r().
     *
     * If your project uses Argon2, libsodium, or another password system,
     * replace this function with that library's password verification method.
    */
    bool verifyPassword(const std::string& password, const std::string& storedHash)
    {
        if (password.empty() || storedHash.empty())
        {
            return false;
        }
        struct crypt_data data{};
        data.initialized = 0;

        char* result = crypt_r(password.c_str(), storedHash.c_str(), &data);

        if (result == nullptr)
        {
            return false;
        }

        return storedHash == result;
    }

    void addExpiredSessionCookie(const drogon::HttpResponsePtr& response)
    {
        response->addHeader(
            "Set-Cookie",
            "session_id=deleted"
            "; Path=/"
            "; Max-Age=0"
            "; Secure"
            "; HttpOnly"
            "; SameSite=Lax");

        response->setStatusCode(drogon::k204NoContent);
    }

    drogon::HttpResponsePtr makeJsonError(drogon::HttpStatusCode status, const std::string& message)
    {
        Json::Value body;
        body["ok"] = false;
        body["error"] = message;

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->setStatusCode(status);
        return response;
    }

} // end of namespace

std::string SessionService::sha256Hex(const std::string& value)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestLength = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context == nullptr)
    {
        throw std::runtime_error("Unable to allocate OpenSSL digest context");
    }

    const bool initialized = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;

    const bool updated = initialized && EVP_DigestUpdate(context, value.data(), value.size()) == 1;

    const bool finalized = updated && EVP_DigestFinal_ex(context, digest.data(), &digestLength) == 1;

    EVP_MD_CTX_free(context);

    if (!finalized)
    {
        throw std::runtime_error("Unable to calculate SHA-256 digest");
    }

    std::ostringstream output;

    for (unsigned int i = 0; i < digestLength; ++i)
    {
        output << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(digest[i]);
    }
    return output.str();
}


bool SessionService::hasSessionToken(const std::string& token)
{
    return isSafeSessionToken(token);
}

bool SessionService::isValidSessionId(const std::string& sessionId)
{
    return hasSessionToken(sessionId);
}

/*
    It is important that generateSessionToken() returns a cryptographically random raw token,
    and that only its SHA-256 hash is stored in the database.
*/

std::string SessionService::generateSessionToken()
{
    std::array<unsigned char, kSessionTokenBytes> bytes{};

    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
    {
        throw std::runtime_error("Unable to generate secure session token");
    }

    std::ostringstream output;

    for (unsigned char byte : bytes)
    {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(byte);
    }

    return output.str();
}

void SessionService::validateAsync(const std::string& sessionToken, Callback&& callback)
{
    auto callbackHolder = std::make_shared<Callback>(std::move(callback));

    if (!hasSessionToken(sessionToken))
    {
        (*callbackHolder)(std::nullopt);
        return;
    }

    auto db = drogon::app().getDbClient("securetiles");

    if (!db)
    {
        LOG_ERROR
            << "Database client is not configured";

        (*callbackHolder)(std::nullopt);
        return;
    }

    const std::string sessionHash = sha256Hex(sessionToken);

    static const std::string sql = R"SQL(
        SELECT
            s.user_id,
            u.can_view_restricted_map
        FROM public.sessions AS s
        JOIN users AS u ON u.id = s.user_id
        WHERE s.session_id_hash = decode($1, 'hex')
          AND s.revoked_at IS NULL
          AND s.expires_at > CURRENT_TIMESTAMP
        LIMIT 1
    )SQL";


    db->execSqlAsync(
        "SELECT current_database(), current_user, inet_server_addr(), inet_server_port()",
        [](const drogon::orm::Result& result) {
            LOG_INFO
                << "Database="
                << result[0][0].as<std::string>()
                << ", user="
                << result[0][1].as<std::string>()
                << ", server="
                << result[0][2].as<std::string>()
                << ":"
                << result[0][3].as<int>();
        },
        [](const drogon::orm::DrogonDbException& exception) {
            LOG_ERROR
                << "Database connectivity test failed: "
                << exception.base().what();
    });

    db->execSqlAsync(
        sql,
        [callbackHolder](const drogon::orm::Result& result)
        {
            if (result.empty())
            {
                LOG_ERROR << "Session lookup returned no rows";
                (*callbackHolder)(std::nullopt);
                return;
            }

            const auto userId = result[0]["user_id"].as<int64_t>();
            AuthenticatedUser authenticatedUser;
            authenticatedUser.id = userId;
            authenticatedUser.canViewRestrictedMap = result[0]["can_view_restricted_map"].as<bool>();

            LOG_INFO << "Session validated for user_id=" << userId << ", can_view_restricted_map=" << authenticatedUser.canViewRestrictedMap;

            (*callbackHolder)(authenticatedUser);

       },
        [callbackHolder](
            const drogon::orm::DrogonDbException& error)
        {
            LOG_ERROR << "Session validation failed: " << error.base().what();

            (*callbackHolder)(std::nullopt);
        },
        sessionHash);

}

void SessionService::createSessionAsync(std::int64_t userId, bool returnRawToken, HttpCallback&& callback)
{
    auto callbackHolder = std::make_shared<HttpCallback>(std::move(callback));

    if (userId <= 0)
    {
        (*callbackHolder)(makeJsonError(drogon::k400BadRequest, "Invalid user ID"));
        return;
    }

    // This is the only raw token.
    const std::string rawToken = generateSessionToken();

    // Store only this hash in PostgreSQL.
    const std::string tokenHash = sha256Hex(rawToken);

    auto db = drogon::app().getDbClient("securetiles");

    if (!db)
    {
        LOG_ERROR << "Database client 'securetiles' is not configured";

        (*callbackHolder)(makeJsonError(drogon::k500InternalServerError, "Database unavailable"));
        return;
    }

    db->execSqlAsync(
        R"SQL(
            INSERT INTO sessions
            (
                user_id,
                session_id_hash,
                expires_at
            )
            VALUES
            (
                $1,
                decode($2, 'hex'),
                CURRENT_TIMESTAMP + INTERVAL '288 hours'
            )
        )SQL",

        [callbackHolder, rawToken, returnRawToken](const drogon::orm::Result&)
        {
            Json::Value body;
            body["ok"] = true;
            body["message"] = "Session created";

            /*
             * Return the raw token only when the caller is the
             * authorized NATS client.
             */
            if (returnRawToken)
            {
                body["session_token"] = rawToken;
            }
            auto response = drogon::HttpResponse::newHttpJsonResponse(body);
            /*
             * The cookie contains the raw token as well.
             * The database contains only its hash.
             */
            SessionService::addSessionCookie(response, rawToken);

            (*callbackHolder)(response);
        },

        [callbackHolder](
            const drogon::orm::DrogonDbException& error)
        {
            LOG_ERROR << "Session insert failed: " << error.base().what();

            (*callbackHolder)(makeJsonError(drogon::k500InternalServerError, "Unable to create session"));
        },

        userId,
        tokenHash);
}

void SessionService::addSessionCookie(const drogon::HttpResponsePtr& response, const std::string& rawToken)
{
    if (!response || !isSafeSessionToken(rawToken))
    {
        return;
    }
    drogon::Cookie cookie("session_id", rawToken);
    cookie.setPath("/");
    cookie.setMaxAge(kSessionLifetimeSeconds);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setSameSite(drogon::Cookie::SameSite::kLax);
    response->addCookie(cookie);
}

std::optional<std::string> SessionService::extractSessionToken(const drogon::HttpRequestPtr& request)
{
    if (!request)
    {
        return {};
    }
    const auto cookie = request->getCookie("session_id");
    if (cookie.empty())
    {
        return std::nullopt;
    }
    return cookie; // this is the raw cookie created by generateSessionToken()
}

void SessionService::login(const drogon::HttpRequestPtr& request, HttpCallback&& callback)
{
    auto callbackHolder = std::make_shared<HttpCallback>(std::move(callback));

    if (!request)
    {
        (*callbackHolder)(jsonError(drogon::k400BadRequest, "Invalid request"));

        return;
    }

    auto json = request->getJsonObject();

    if (!json)
    {
        (*callbackHolder)(jsonError(drogon::k400BadRequest,"JSON body required"));

        return;
    }

    const std::string email = getJsonString(*json, "email");

    const std::string password = getJsonString(*json, "password");

    if (email.empty() || email.size() > 320 || password.empty() || password.size() > 1024)
    {
        (*callbackHolder)(jsonError(drogon::k401Unauthorized,"Invalid credentials"));

        return;
    }

    auto db = drogon::app().getDbClient("securetiles");

    if (!db)
    {
        LOG_ERROR << "Database client is not configured";

        (*callbackHolder)(jsonError(drogon::k500InternalServerError, "Authentication service unavailable"));

        return;
    }

    static const std::string sql = R"SQL(
        SELECT
            id,
            password_hash
        FROM users
        WHERE lower(email) = lower($1)
        LIMIT 1
    )SQL";

    if (!db)
    {
        LOG_ERROR << "Drogon database client 'securetiles' is null";

        (*callbackHolder)(jsonError(drogon::k500InternalServerError, "Authentication service unavailable"));
        return;
    }

    db->execSqlAsync(sql,[callbackHolder, password](const drogon::orm::Result& result)
        {
            /*
             * Return the same response for an unknown email and a wrong
             * password. This avoids revealing whether an account exists.
             */
            if (result.empty())
            {
                (*callbackHolder)(jsonError(drogon::k401Unauthorized,"Invalid credentials"));

                return;
            }

            const std::string storedHash = result[0]["password_hash"].as<std::string>();

            if (!verifyPassword(password,storedHash))
            {
                (*callbackHolder)(jsonError(drogon::k401Unauthorized, "Invalid credentials"));

                return;
            }

            const std::int64_t userId = result[0]["id"].as<std::int64_t>();

            /*
             * Create the session after successful authentication.
             * A separate callback holder is used because the original
             * callback must be forwarded to createSessionAsync().
             */

            /*
             * The login endpoint already creates the session cookie (SessionService::addSessionCookie)
             * and invokes this method through createSessionAsync():
             * The resulting response contains:
             * Set-Cookie: session_id=<raw-token>; Path=/; Max-Age=1036800; Secure; HttpOnly; SameSite=Lax
            */

            SessionService::createSessionAsync(
                userId,
                false,
                [callbackHolder](
                    const drogon::HttpResponsePtr& response)
                {
                    (*callbackHolder)(response);
                });

        },
        [callbackHolder](
            const drogon::orm::DrogonDbException& error)
        {
            LOG_ERROR
                << "Login query failed: "
                << error.base().what();

            (*callbackHolder)(
                jsonError(
                    drogon::k500InternalServerError,
                    "Authentication service unavailable"));
        },
        email);
}

void SessionService::logout(const drogon::HttpRequestPtr& request, HttpCallback&& callback)
{
    auto callbackHolder = std::make_shared<HttpCallback>(std::move(callback));

    if (!request)
    {
        (*callbackHolder)(jsonError(drogon::k400BadRequest,"Invalid request"));

        return;
    }

    const std::string rawToken = request->getCookie("session_id");

    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k204NoContent);
    response->addHeader(
        "Set-Cookie",
        "session_id=deleted"
        "; Max-Age=0"
        "; Path=/"
        "; Secure"
        "; HttpOnly"
        "; SameSite=Lax");

    if (!hasSessionToken(rawToken))
    {
        (*callbackHolder)(response);
        return;
    }

    const std::string tokenHash = sha256Hex(rawToken);

    auto db = drogon::app().getDbClient("securetiles");

    if (!db)
    {
        LOG_ERROR << "Database client is not configured";
        (*callbackHolder)(jsonError(drogon::k500InternalServerError, "Authentication service unavailable"));
        return;
    }

    static const std::string sql = R"SQL(
        UPDATE sessions
        SET revoked_at = CURRENT_TIMESTAMP
        WHERE session_id_hash = decode($1, 'hex')
          AND revoked_at IS NULL
    )SQL";

    db->execSqlAsync(
        sql,
        [callbackHolder,
         response](
            const drogon::orm::Result&)
        {
            (*callbackHolder)(response);
        },
        [callbackHolder](const drogon::orm::DrogonDbException& error)
        {
            LOG_ERROR << "Logout failed: " << error.base().what();
            (*callbackHolder)(jsonError(drogon::k500InternalServerError, "Unable to log out"));
        },
        tokenHash);
}
