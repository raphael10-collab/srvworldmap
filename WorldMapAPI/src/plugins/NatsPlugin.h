#pragma once

#include <drogon/drogon.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <stdlib.h>
#include <cstdint>

#include <iomanip>
#include <sstream>

#include <nats/nats.h>

#include "../services/MapCommandService.h"

/*
    A plugin gives you a clear lifecycle:

    Drogon starts
      → plugin initAndStart()
      → NATS connects and subscribes
      → HTTP server runs
    Drogon stops
      → plugin shutdown()
      → unsubscribe/drain/close NATS

Drogon plugins are suitable for long-lived infrastructure
such as
    NATS clients,
    database-independent services,
    metrics,
    and background workers

Drogon itself is asynchronous and supports
    filter chains,
    WebSockets,
    and asynchronous database access
*/


/*
    important design:
    - own the connection inside the plugin;
    - subscribe during startup;
    - unsubscribe and close during shutdown;
    - prevent callbacks from using destroyed application objects.

*/

enum class PublishResult
{
    Published,
    Stopping,
    NotConnected,
    Failed
};

class NatsPlugin : public drogon::Plugin<NatsPlugin>
{
    public:
        NatsPlugin() = default;
        ~NatsPlugin() override = default;

        void initAndStart(const Json::Value& config);
        void shutdown() override;

        bool isConnected() const;

        PublishResult publish(const std::string& subject, const std::string& payload);

    private:
        std::string bcryptHash(const std::string& password);
        void createOrResetUser(const bool canViewRestrictedMap, const std::string& email, const std::string& password);

        static std::string toHex(const std::string& value);

        static bool isJsonPayload(const std::string& payload);

        static void onNatsMessage(natsConnection* connection, natsSubscription* subscription, natsMsg* message, void* closure);

        static void onNatsConnectionEvent(natsConnection* connection, void* closure);

        static void onNatsDisconnected(natsConnection* connection, void* closure);

        static void onNatsReconnected(natsConnection* connection, void* closure);

        void publishLoginError(const std::string& replySubject,const std::string& message);

        void handleLogin(const std::string& payload, const std::string& replySubject);

        void handleMessage(const std::string& subject,const std::string& payload,const std::string& replySubject);

        mutable std::mutex mutex_;

        std::shared_ptr<MapCommandService> commandService_;

        natsOptions      *opts_ = NULL;
        natsConnection   *conn_ = NULL;
        natsSubscription *markerSub_ = NULL;
        natsSubscription *loginSub_ = NULL;
        natsMsg          *msg_ = NULL;
        natsStatus        status_ = NATS_OK;

        const char *caFile = "/root/nats-certs/nats-ca.crt";

        const char *clientCertFile = "/root/nats-certs/client-b.crt";

        const char *clientKeyFile = "/root/nats-certs/client-b.key";

        std::string server_;
        std::string subject_;
        std::string queue_group_;

        bool stopping_{false};
        bool connected_{false};
};
