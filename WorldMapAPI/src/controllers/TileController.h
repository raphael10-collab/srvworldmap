#pragma once

#include <drogon/HttpController.h>
#include <functional>
#include <memory>

class TileController : public drogon::HttpController<TileController, false>
{
    public:
    METHOD_LIST_BEGIN

    //METHOD_ADD(TileController::getRestrictedTile, "/api/restricted-tiles/{z}/{x}/{y}.pbf", drogon::Get, "AuthFilter");
    //METHOD_ADD(TileController::health, "/api/restricted-tiles-health", drogon::Get);

    ADD_METHOD_TO(TileController::getRestrictedTile, "/api/restricted-tiles/{z}/{x}/{y}.pbf", drogon::Get, "AuthFilter");
    ADD_METHOD_TO(TileController::health, "/api/restricted-tiles-health", drogon::Get);


    METHOD_LIST_END

    void getRestrictedTile(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback, int z, int x, int y);

    void health(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback);
};
