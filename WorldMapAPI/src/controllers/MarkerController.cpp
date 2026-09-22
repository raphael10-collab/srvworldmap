#include "MarkerController.h"

#include "../plugins/NatsPlugin.h"
#include "../services/SessionService.h"

#include <json/json.h>

namespace
{
    using Callback = std::function<void(const drogon::HttpResponsePtr&)>;

    drogon::HttpResponsePtr jsonErrorResponse(drogon::HttpStatusCode status, const std::string& message)
    {
        Json::Value body;
        body["ok"] = false;
        body["error"] = message;

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->setStatusCode(status);
        response->addHeader("Cache-Control", "no-store");
        response->addHeader("X-Content-Type-Options", "nosniff");

        return response;
    }
}

void MarkerController::createMarker(const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback)
{
    if (!request)
    {
        callback(jsonErrorResponse(drogon::k400BadRequest, "Invalid request"));
        return;
    }

    auto json = request->getJsonObject();

    if (!json || !json->isObject())
    {
        callback(jsonErrorResponse(drogon::k400BadRequest, "JSON body required"));
        return;
    }

    if (!json->isMember("longitude") || !json->isMember("latitude") || !json->isMember("title") || !json->isMember("description"))
    {
        callback(jsonErrorResponse(drogon::k400BadRequest, "Missing marker fields"));
        return;
    }

    if (!(*json)["longitude"].isNumeric() || !(*json)["latitude"].isNumeric() || !(*json)["title"].isString() || !(*json)["description"].isString())
    {
        callback(jsonErrorResponse(drogon::k400BadRequest, "Invalid marker fields"));
        return;
    }

    /*
     * AuthFilter has already validated the cookie and inserted user_id
     * into the request attributes. We still retrieve the raw cookie here
     * because it is needed by the asynchronous NATS consumer.
     */
    SessionService sessionservice;
    const std::optional<std::string> rawToken = sessionservice.extractSessionToken(request);

    if(!rawToken.has_value())
    {
        callback(jsonErrorResponse(drogon::k401Unauthorized, "Invalid session token"));
        return;
    }

    Json::Value natsPayload;

    /*
     * This must be the raw token from the session_id cookie.
     * Do not use the session_id_hash database value here.
     */
    natsPayload["session_token"] = rawToken.value();

    natsPayload["longitude"] = (*json)["longitude"].asDouble();

    natsPayload["latitude"] = (*json)["latitude"].asDouble();

    natsPayload["title"] = (*json)["title"].asString();

    natsPayload["description"] = (*json)["description"].asString();

    Json::StreamWriterBuilder writerBuilder;
    writerBuilder["indentation"] = "";

    const std::string payload = Json::writeString(writerBuilder, natsPayload);

    auto* natsPlugin = drogon::app().getPlugin<NatsPlugin>();

    if (natsPlugin == nullptr)
    {
        callback(
            jsonErrorResponse(drogon::k503ServiceUnavailable, "NATS service unavailable"));
        return;
    }

    const PublishResult result = natsPlugin->publish("map.marker.create", payload);

    switch (result)
    {
        case PublishResult::Published:
        {
            Json::Value responseBody;
            responseBody["ok"] = true;
            responseBody["message"] = "Marker command published";

            auto response = drogon::HttpResponse::newHttpJsonResponse(responseBody);

            response->setStatusCode(drogon::k202Accepted);
            callback(response);
            return;
        }

        case PublishResult::Stopping:
        case PublishResult::NotConnected:
        {
            callback(
                jsonErrorResponse(drogon::k503ServiceUnavailable, "NATS is not connected"));
            return;
        }

        case PublishResult::Failed:
        default:
        {
            callback(jsonErrorResponse(drogon::k500InternalServerError, "Unable to publish marker command"));
            return;
        }
    }
}


void MarkerController::getRestrictedMarkers(const drogon::HttpRequestPtr& request, Callback&& callback)
{
    auto callbackHolder = std::make_shared<Callback>(std::move(callback));
    SessionService sessionservice;
    const std::optional<std::string> rawToken = sessionservice.extractSessionToken(request);
    if (!rawToken.has_value())
    {
        (*callbackHolder)(jsonErrorResponse(drogon::k401Unauthorized, "Authentication required"));
        return;
    }

    SessionService::validateAsync(
        rawToken.value(),
        [callbackHolder](
            std::optional<AuthenticatedUser> authenticatedUser) mutable
        {
            if (!authenticatedUser.has_value())
            {
                (*callbackHolder)(jsonErrorResponse(drogon::k401Unauthorized, "Authentication required"));
                return;
            }

            if (!authenticatedUser->canViewRestrictedMap)
            {
                (*callbackHolder)(jsonErrorResponse(drogon::k403Forbidden, "Restricted-map permission required"));
                return;
            }

            auto dbClient = drogon::app().getDbClient("securetiles");

            if (!dbClient)
            {
                (*callbackHolder)(jsonErrorResponse(drogon::k500InternalServerError, "Database unavailable"));
                return;
            }

            static const std::string sql = R"SQL(
                SELECT
                    id,
                    name,
                    properties,
                    ST_AsGeoJSON(geom)::text AS geometry
                FROM restricted_features
                WHERE owner_user_id = $1
                ORDER BY id
            )SQL";

            const auto userId = authenticatedUser->id;

            dbClient->execSqlAsync(
                sql,

                // Success callback
                [callbackHolder](const drogon::orm::Result& result) mutable
                {
                    Json::Value featureCollection;
                    featureCollection["type"] = "FeatureCollection";
                    featureCollection["features"] = Json::arrayValue;

                    for (const auto& row : result)
                    {
                        Json::Value feature;
                        feature["type"] = "Feature";
                        feature["id"] = Json::Int64(row["id"].as<int64_t>());

                        Json::Value geometry;
                        Json::CharReaderBuilder readerBuilder;
                        std::string parseErrors;

                        std::istringstream geometryStream( row["geometry"].as<std::string>());

                        if (!Json::parseFromStream(readerBuilder, geometryStream, &geometry, &parseErrors))
                        {
                            LOG_ERROR
                                << "Invalid geometry JSON for marker "
                                << row["id"].as<int64_t>()
                                << ": "
                                << parseErrors;
                            continue;
                        }

                        feature["geometry"] = geometry;

                        Json::Value properties(Json::objectValue);

                        if (!row["name"].isNull())
                        {
                            properties["name"] = row["name"].as<std::string>();
                        }

                        if (!row["properties"].isNull())
                        {
                            Json::CharReaderBuilder propertiesBuilder;
                            std::string propertiesErrors;
                            Json::Value storedProperties;

                            std::istringstream propertiesStream(row["properties"].as<std::string>());

                            if (Json::parseFromStream(propertiesBuilder, propertiesStream, &storedProperties, &propertiesErrors) && storedProperties.isObject())
                            {
                                for (const auto& key : storedProperties.getMemberNames())
                                {
                                    properties[key] = storedProperties[key];
                                }
                            }
                        }
                        feature["properties"] = properties;
                        featureCollection["features"].append(feature);
                    }

                    auto response = drogon::HttpResponse::newHttpJsonResponse(featureCollection);

                    response->setStatusCode(drogon::k200OK);
                    response->addHeader("Cache-Control", "private, no-store");
                    response->addHeader("X-Content-Type-Options", "nosniff");

                    (*callbackHolder)(response);
                },

                // Error callback
                [callbackHolder](const drogon::orm::DrogonDbException& error) mutable
                {
                    LOG_ERROR << "Marker query failed: " << error.base().what();

                    (*callbackHolder)(jsonErrorResponse(drogon::k500InternalServerError, "Marker query failed"));
                },

                userId);
        });
}
