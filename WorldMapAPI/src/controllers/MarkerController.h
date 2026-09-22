#pragma once

#include <drogon/HttpController.h>

class MarkerController: public drogon::HttpController<MarkerController>
{
    public:
        METHOD_LIST_BEGIN

        ADD_METHOD_TO(
            MarkerController::createMarker,
            "/api/restricted-markers",
            drogon::Post,
            "AuthFilter");

        ADD_METHOD_TO(
            MarkerController::getRestrictedMarkers,
            "/api/restricted-markers",
            drogon::Get
        );

        METHOD_LIST_END

        void createMarker(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback);

        void getRestrictedMarkers(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback);
};
