#pragma once

#include <drogon/HttpController.h>

class AuthController
    : public drogon::HttpController<AuthController>
{
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(
        AuthController::establishSession,
        "/api/auth/session",
        drogon::Post);

    ADD_METHOD_TO(
        AuthController::login,
        "/api/auth/login",
        drogon::Post);

    ADD_METHOD_TO(
        AuthController::access,
        "/api/auth/access",
        drogon::Get);

    ADD_METHOD_TO(
        AuthController::logout,
        "/api/auth/logout",
        drogon::Post);

    METHOD_LIST_END

    void establishSession(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback);
    void login(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback);
    void access(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback);
    void logout(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback);
};
