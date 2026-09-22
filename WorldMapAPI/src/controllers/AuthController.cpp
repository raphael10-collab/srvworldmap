#include "AuthController.h"
#include "../services/SessionService.h"

void AuthController::establishSession(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    if (!request)
    {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k400BadRequest);
        callback(response);
        return;
    }
    const std::string cookie = request->getCookie("session_id");
    LOG_INFO << "Auth access cookie present: " << (!cookie.empty() ? "yes" : "no") << ", length=" << cookie.size();

    const auto json = request->getJsonObject();

    if (!json || !json->isMember("session_token") || !(*json)["session_token"].isString())
    {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k400BadRequest);
        response->setBody("Missing session_token");
        callback(response);
        return;
    }

    const std::string token = (*json)["session_token"].asString();

    if (!SessionService::isValidSessionId(token))
    {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k400BadRequest);
        response->setBody("Invalid session_token");
        callback(response);
        return;
    }

    SessionService::validateAsync(token, [token, callback = std::move(callback)](std::optional<AuthenticatedUser> user) mutable
    {
        if (!user.has_value())
        {
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setStatusCode(drogon::k401Unauthorized);
            response->setBody("Invalid or expired session");
            callback(response);
            return;
        }

        Json::Value body;
        body["ok"] = true;
        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->addHeader(
            "Set-Cookie",
            "session_id=" + token +
            "; Max-Age=1036800"
            "; Path=/"
            "; Secure"
            "; HttpOnly"
            "; SameSite=Lax"
        );
        callback(response);
    });
}

void AuthController::login(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    SessionService::login(request, std::move(callback));
}

void AuthController::access(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    if (!request)
    {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k400BadRequest);
        callback(response);
        return;
    }

    SessionService service;
    const auto token = service.extractSessionToken(request);

    if (!token.has_value())
    {
        Json::Value body;
        body["authenticated"] = false;
        body["authorized"] = false;
        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->setStatusCode(drogon::k401Unauthorized);
        response->addHeader("Cache-Control", "no-store");
        callback(response);
        return;
    }

    SessionService::validateAsync(
        token.value(),
        [callback = std::move(callback)](
            std::optional<AuthenticatedUser> user) mutable
        {
            Json::Value body;

            if (!user.has_value())
            {
                body["authenticated"] = false;
                body["authorized"] = false;

                auto response = drogon::HttpResponse::newHttpJsonResponse(body);
                response->setStatusCode(drogon::k401Unauthorized);
                response->addHeader("Cache-Control", "no-store");
                callback(response);
                return;
            }
            body["authenticated"] = true;
            body["authorized"] = user->canViewRestrictedMap;
            body["user_id"] = Json::Int64(user->id);
            auto response = drogon::HttpResponse::newHttpJsonResponse(body);
            response->setStatusCode(drogon::k200OK);
            response->addHeader("Cache-Control", "no-store");
            response->addHeader("X-Content-Type-Options", "nosniff");
            callback(response);
        });
}


void AuthController::logout(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    SessionService::logout(request, std::move(callback));
}
