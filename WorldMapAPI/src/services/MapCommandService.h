/*
 the service has application-wide state or dependencies and should be managed by Drogon
*/

#pragma once

#include <drogon/drogon.h>
#include <string>

class MapCommandService: public drogon::Plugin<MapCommandService>
{
    public:
        void initAndStart(const Json::Value& config) override;
        void shutdown() override;
        void handle(const std::string& subject, const std::string& payload);
        bool authenticateUser(const std::string& username, const std::string& password);
        std::string createSessionForUser(const std::string& email);
};
