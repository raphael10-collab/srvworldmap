#include "TileController.h"

#include "../services/TileService.h"

void TileController::health(const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setContentTypeCode(drogon::CT_TEXT_PLAIN);
    response->setBody("TileController is registered\n");
    callback(response);
}

void TileController::getRestrictedTile(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback, int z, int x, int y)
{
    LOG_INFO << "Restricted tile request received: z=" << z << ", x=" << x << ", y=" << y;

    std::int64_t userId = 0;

    try
    {
        userId = request->getAttributes()->get<std::int64_t>("user_id");
    }
    catch (const std::exception& error)
    {
        LOG_ERROR << "Missing authenticated user_id: " << error.what();

        auto response = drogon::HttpResponse::newHttpResponse(drogon::k401Unauthorized, drogon::CT_NONE);
        response->addHeader("Cache-Control", "no-store");
        callback(response);
        return;
    }

    if (userId <= 0)
    {
        auto response = drogon::HttpResponse::newHttpResponse(drogon::k401Unauthorized, drogon::CT_NONE);
        response->addHeader("Cache-Control", "no-store");
        callback(response);
        return;
    }

    TileService::getRestrictedTile(
        userId,
        z,
        x,
        y,
        [callback = std::move(callback)](
            bool success,
            std::string tileData,
            std::string errorMessage) mutable
        {
            if (!success)
            {
                LOG_ERROR << "Tile request failed: " << errorMessage;

                auto response = drogon::HttpResponse::newHttpResponse(drogon::k500InternalServerError, drogon::CT_NONE);
                response->addHeader("Cache-Control", "private, no-store");
                callback(response);
                return;
            }

            auto response = drogon::HttpResponse::newHttpResponse();
            response->addHeader("Content-Type", "application/vnd.mapbox-vector-tile");
            response->addHeader("Cache-Control", "private, no-store");
            response->addHeader("X-Content-Type-Options", "nosniff");
            response->setBody(std::move(tileData));
            response->setContentTypeString("application/vnd.mapbox-vector-tile");
            callback(response);
        });
}
