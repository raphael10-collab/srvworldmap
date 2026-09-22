#pragma once

#include <drogon/drogon.h>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>



struct AuthenticatedUser
{
    std::int64_t id{0};
    bool canViewRestrictedMap{false};
};


/*
    users table contains:
        - id bigint primary key,
        - email text unique not null,
        - password_hash text not null,
        - can_view_restricted_map boolean not null default false

*/

/*
    The verifyPassword() function must use the same password-hashing library used when user passwords are created
*/

class SessionService
{
    public:
        using Callback = std::function<void(std::optional<AuthenticatedUser>)>;

        using HttpCallback = std::function<void(const drogon::HttpResponsePtr&)>;
        /*
         * Validates a raw session token received from the session_id cookie.
         *
         * The raw token is never stored directly in the database.
         * It is hashed before lookup.
        */
        static void validateAsync(const std::string& rawToken, Callback&& callback);
        /*
         * Creates a session after the caller has authenticated a user.
        */
        static void createSessionAsync(std::int64_t userId, bool returnRawToken, HttpCallback&& callback);
        /*
         * Authenticates the login request and creates a session cookie.
         *
         * Expected JSON:
         * {
         *   "email": "user@example.com",
         *   "password": "password"
         * }
        */
        static void login(const drogon::HttpRequestPtr& request, HttpCallback&& callback);
        /*
         * Revokes the current session and expires the browser cookie.
        */
        static void logout(const drogon::HttpRequestPtr& request, HttpCallback&& callback);
        /*
         * Generates a cryptographically secure random token.
        */
        static std::string generateSessionToken();

        static std::string sha256Hex(const std::string& value);

        /*
         * Validates the syntax of a raw token.
        */
        static bool hasSessionToken( const std::string& token);
        /*
         * Kept as an alias for compatibility with existing code.
        */
        static bool isValidSessionId(const std::string& sessionId);
        // Gets the raw token from the HTTP cookie.
        std::optional<std::string> extractSessionToken(const drogon::HttpRequestPtr& request);
    private:
        // Use this only for a trusted NATS client over TLS. Do not expose the raw token to logs or untrusted browser code.
        static void addSessionCookie(const drogon::HttpResponsePtr& response, const std::string& rawToken);
};
