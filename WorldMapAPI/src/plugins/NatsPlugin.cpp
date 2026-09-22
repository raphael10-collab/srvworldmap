#include "NatsPlugin.h"
#include <stdexcept>
#include <crypt.h>

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

void NatsPlugin::initAndStart(const Json::Value& config)
{
    server_ = config.get(
        "server",
        "tls://10.50.0.2:4222").asString();

    subject_ = config.get(
        "subject",
        "map.marker.create").asString();

    queue_group_ = config.get(
        "queue_group",
        "worldmap-api").asString();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = false;
    }

    commandService_ = std::make_shared<MapCommandService>();

    natsOptions* options = nullptr;
    natsStatus status = natsOptions_Create(&options);
    if (status != NATS_OK)
    {
        throw std::runtime_error("Unable to create NATS options");
    }

    status = natsOptions_SetURL(options, server_.c_str());
    if (status != NATS_OK)
    {
        throw std::runtime_error("Unable to set NATS URL");
    }

    // Equivalent to: --tlsca /root/nats-certs/nats-ca.crt
    status = natsOptions_LoadCATrustedCertificates(options, caFile);
    if (status != NATS_OK)
    {
        throw std::runtime_error("NATS-Unable to load CA Trusted Certificates");
    }

    /*
     * Equivalent to:
     * --tlscert /root/nats-certs/client-a/client-b.crt
     * --tlskey  /root/nats-certs/client-a/client-b.key
    */
    status = natsOptions_LoadCertificatesChain(options, clientCertFile, clientKeyFile);
    if (status != NATS_OK)
    {
        throw std::runtime_error("Unable to Load Certificates Chain: " + std::string(natsStatus_GetText(status)));
    }

    natsOptions_SetDisconnectedCB(options, &NatsPlugin::onNatsDisconnected, this);

    natsOptions_SetReconnectedCB(options, &NatsPlugin::onNatsReconnected, this);

    status = natsConnection_Connect(&conn_, options);

    natsOptions_Destroy(options);

    if (status != NATS_OK)
    {
        conn_ = nullptr;

        throw std::runtime_error("Unable to connect to NATS: " + std::string(natsStatus_GetText(status)));
    }

    createOrResetUser(true, "alice@example.com", "alice_pwd");

    status = natsConnection_Subscribe(&loginSub_, conn_, "auth.login.request", &NatsPlugin::onNatsMessage, this);

    if (status != NATS_OK)
    {
        natsConnection_Close(conn_);
        natsConnection_Destroy(conn_);
        conn_ = nullptr;

        throw std::runtime_error("Unable to subscribe to NATS: " + std::string(natsStatus_GetText(status)));
        LOG_ERROR << "Failed to subscribe to auth.login.request: " << natsStatus_GetText(status);
        return;
    }

    status = natsConnection_Subscribe(&markerSub_, conn_, "map.marker.create", &NatsPlugin::onNatsMessage, this);

    if (status != NATS_OK)
    {
        natsConnection_Close(conn_);
        natsConnection_Destroy(conn_);
        conn_ = nullptr;

        throw std::runtime_error("Unable to subscribe to NATS: " + std::string(natsStatus_GetText(status)));
        LOG_ERROR << "Failed to subscribe to map.marker.create: " << natsStatus_GetText(status);
        return;
    }


    {
        std::lock_guard<std::mutex> lock(mutex_);
        connected_ = true;
    }

    LOG_INFO << "NATS connected to " << server_ << ", subscribed to " << subject_;

}

void NatsPlugin::onNatsDisconnected(natsConnection*, void* closure)
{
    auto* plugin = static_cast<NatsPlugin*>(closure);

    if (plugin == nullptr)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(plugin->mutex_);
        plugin->connected_ = false;
    }

    LOG_WARN << "NATS disconnected";
}

void NatsPlugin::onNatsReconnected(natsConnection* connection, void* closure)
{
    auto* plugin = static_cast<NatsPlugin*>(closure);

    if (plugin == nullptr)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(plugin->mutex_);
        plugin->connected_ = true;
    }
    char* connection_url;
    LOG_INFO << "NATS reconnected to " << natsConnection_GetConnectedUrl(connection, connection_url, 1000);
}

/*

  For nats.c, the connection can be used by multiple application threads, but your code must still protect the lifetime of natsConnection.
  The critical rule is:
    publish() and shutdown() must not use or destroy the connection concurrently.
  Therefore, hold the same mutex during the entire publish operation and during connection destruction.
  Do not copy conn_ under the mutex and unlock before publishing;
  shutdown could destroy it immediately afterward.

*/

PublishResult NatsPlugin::publish(const std::string& subject, const std::string& payload)
{

    /*

        This is safe because:
        - mutex_ protects connection_, stopping_, and connected_;
        - shutdown() cannot destroy the connection while natsConnection_PublishString() is running;
        - multiple callers cannot simultaneously enter your publish/shutdown lifecycle section.

        The NATS C client handles normal concurrent use of a connection,
        but object destruction must still be coordinated by the application.
    */

    std::lock_guard<std::mutex> lock(mutex_);

    if (stopping_)
    {
        return PublishResult::Stopping;
    }

    if ((conn_ == nullptr ) || (!connected_))
    {
        return PublishResult::NotConnected;
    }

    auto status = natsConnection_Status(conn_);
    if (status == NATS_CONN_STATUS_CLOSED || status == NATS_CONN_STATUS_DRAINING_SUBS)
    {
        return PublishResult::NotConnected;
    }

    natsStatus status2 = natsConnection_PublishString(conn_, subject.c_str(), payload.c_str());
    if (status2 != NATS_OK)
    {
        LOG_ERROR
            << "NATS publish failed for subject '"
            << subject
            << "': "
            << natsStatus_GetText(status2);

        return PublishResult::Failed;
    }

    status2 = natsConnection_FlushTimeout(conn_, 1000);

    if (status2 != NATS_OK)
    {
        LOG_ERROR
            << "NATS flush failed: "
            << natsStatus_GetText(status2);

        return PublishResult::Failed;
    }

    return PublishResult::Published;
}


std::string NatsPlugin::bcryptHash(const std::string& password)
{
    struct crypt_data data{};
    data.initialized = 0;

    char salt[CRYPT_GENSALT_OUTPUT_SIZE]{};

    if (crypt_gensalt_rn("$2b$", 12, nullptr, 0, salt, sizeof(salt)) == nullptr)
    {
        throw std::runtime_error("Unable to generate bcrypt salt");
    }

    char* result = crypt_r(password.c_str(), salt, &data);

    if (result == nullptr)
    {
        throw std::runtime_error("Unable to generate bcrypt password hash");
    }
    return std::string(result);
}

void NatsPlugin::createOrResetUser(const bool canViewRestrictedMap, const std::string& email, const std::string& password)
{
    auto dbClient = drogon::app().getDbClient("securetiles");

    if (!dbClient)
    {
        throw std::runtime_error("Database client 'securetiles' is unavailable");
    }

    const std::string passwordHash = bcryptHash(password);

    dbClient->execSqlAsync(
        R"SQL(
            INSERT INTO users
            (
                can_view_restricted_map,
                email,
                password_hash
            )
            VALUES
            (
                $1,
                $2,
                $3
            )
            ON CONFLICT (email)
            DO UPDATE SET
                password_hash = EXCLUDED.password_hash,
                can_view_restricted_map =
                    EXCLUDED.can_view_restricted_map
        )SQL",

        [](const drogon::orm::Result&)
        {
            LOG_INFO
                << "User created or reset successfully";
        },

        [](const drogon::orm::DrogonDbException& exception)
        {
            LOG_ERROR
                << "Unable to create or reset Alice: "
                << exception.base().what();
        },

        canViewRestrictedMap,
        email,
        passwordHash);
}

void NatsPlugin::shutdown()
{

    /*
        -> mark the service as stopping
        -> detach the pointers
        -> unsubscribe
        -> flush if needed
        ->then close and destroy.
    */

    /*
        Because shutdown() holds mutex_, it waits for any active publish() call to finish.
    */

    std::lock_guard<std::mutex> lock(mutex_);

    if (stopping_)
    {
        return;
    }

    stopping_ = true;
    connected_ = false;

    if (markerSub_ != nullptr)
    {
        natsSubscription_Unsubscribe(markerSub_);
        natsSubscription_Destroy(markerSub_);
        markerSub_ = nullptr;
    }

    if (loginSub_ != nullptr)
    {
        natsSubscription_Unsubscribe(loginSub_);
        natsSubscription_Destroy(loginSub_);
        loginSub_ = nullptr;
    }

    if (conn_ != nullptr)
    {
        // Flush messages already accepted by the client library.
        natsConnection_FlushTimeout(conn_, 1000);

        natsConnection_Close(conn_);
        natsConnection_Destroy(conn_);
        conn_ = nullptr;
    }

    LOG_INFO << "NATS plugin stopped";
}

bool NatsPlugin::isConnected() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return conn_ != nullptr && connected_ && !stopping_;
}

std::string NatsPlugin::toHex(const std::string& value)
{
    std::ostringstream output;
    for (unsigned char byte : value)
    {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(byte)
               << ' ';
    }
    return output.str();
}

bool NatsPlugin::isJsonPayload(const std::string& payload)
{
    Json::Value document;
    Json::CharReaderBuilder builder;
    std::string errors;
    std::istringstream stream(payload);

    return Json::parseFromStream(builder, stream, &document, &errors);
}

void NatsPlugin::onNatsMessage(natsConnection*, natsSubscription*, natsMsg* message, void* closure)
{

    /*
        Do not perform slow work directly inside the NATS callback.
        Convert the message into an application task and dispatch it to Drogon’s event loop or a worker queue.
    */

    auto* plugin = static_cast<NatsPlugin*>(closure);

    if (plugin == nullptr)
    {
        if (message != nullptr)
        {
            natsMsg_Destroy(message);
        }
        return;
    }

    const char* subjectValue = natsMsg_GetSubject(message);
    const char* replyValue = natsMsg_GetReply(message);

    const std::string subject = subjectValue != nullptr ? subjectValue : "";

    const std::string replySubject = replyValue != nullptr ? replyValue : "";

    const std::string payload(natsMsg_GetData(message), natsMsg_GetDataLength(message));

    LOG_INFO
        << "Received NATS message"
        << ", subject=" << subject
        << ", reply=" << replySubject;

    natsMsg_Destroy(message);

    plugin->handleMessage(subject, payload, replySubject);

}

void NatsPlugin::publishLoginError(const std::string& replySubject, const std::string& message)
{
    if (replySubject.empty())
    {
        LOG_ERROR << "Cannot send login error without reply subject";
        return;
    }

    Json::Value response;
    response["ok"] = false;
    response["message"] = message;

    Json::StreamWriterBuilder writer;
    writer["indentation"] = "";

    const std::string payload = Json::writeString(writer, response);

    natsStatus status = natsConnection_Publish(conn_, replySubject.c_str(), payload.data(), static_cast<int>(payload.size()));

    if (status != NATS_OK)
    {
        LOG_ERROR << "Failed to publish login error: " << natsStatus_GetText(status);
        return;
    }
    natsConnection_FlushTimeout(conn_, 1000);
}

void NatsPlugin::handleLogin(const std::string& payload, const std::string& replySubject)
{
    LOG_INFO << "Handling login request";
    LOG_INFO << "Reply subject: " << replySubject;


    Json::Value request;
    Json::CharReaderBuilder reader;
    std::string errors;
    std::istringstream input(payload);

    if (!Json::parseFromStream(reader, input, &request, &errors))
    {
        publishLoginError(replySubject, "Invalid JSON");
        return;
    }

    const std::string username = request.get("username", "").asString();

    const std::string password = request.get("password", "").asString();

    if (username.empty() || password.empty())
    {
        publishLoginError(replySubject, "Username and password are required");
        return;
    }

    bool authenticated = commandService_->authenticateUser(username, password);

   if (!authenticated)
    {
        publishLoginError(replySubject, "Invalid credentials");
        return;
    }

    if (replySubject.empty())
    {
        LOG_ERROR << "Login request has no reply subject";
        return;
    }

    try
    {
        const std::string sessionToken = commandService_->createSessionForUser(username);

        Json::Value response;
        response["ok"] = true;
        response["message"] = "Session created";
        response["session_token"] = sessionToken;

        Json::StreamWriterBuilder writer;
        writer["indentation"] = "";

        const std::string responsePayload = Json::writeString(writer, response);
        const natsStatus status = natsConnection_Publish(conn_, replySubject.c_str(), responsePayload.data(), static_cast<int>(responsePayload.size()));

        if (status != NATS_OK)
        {
            LOG_ERROR << "Failed to publish login response: " << natsStatus_GetText(status);
            return;
        }

        const natsStatus flushStatus = natsConnection_FlushTimeout(conn_, 1000);

        if (flushStatus != NATS_OK)
        {
            LOG_ERROR << "Failed to flush login response: " << natsStatus_GetText(flushStatus);
            return;
        }
        LOG_INFO << "Login response sent";
        // If this works, it shouild print:
        // Login response: {"message":"Session created","ok":true,"session_token":"temporary-test-token"}
        // Then replace the temporary token with your real authentication and session-creation logic.
    }
    catch (const std::exception& exception)
    {
        LOG_ERROR << "Session creation failed: " << exception.what();
        publishLoginError(replySubject, "Unable to create session");
    }
}

// Dispatch the actual processing:
void NatsPlugin::handleMessage(const std::string& subject, const std::string& payload, const std::string& replySubject)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (stopping_ || ! commandService_)
        {
            return;
        }
    }
    // Keep the NATS callback lightweight.
    drogon::app().getLoop()->queueInLoop(
        [subject, payload, this, replySubject]()
        {
            if (subject == "auth.login.request")
            {
                handleLogin(payload, replySubject);
                return;
            }

            std::shared_ptr<MapCommandService> service;

            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (stopping_)
                {
                    return;
                }
                service = commandService_;
            }

            if (!isJsonPayload(payload))
            {
                LOG_ERROR << "Ignoring non-JSON NATS payload on subject " << subject << ", bytes=" << payload.size() << ", hex=" << toHex(payload);
                return;
            }

            // Process the command here, or hand it to
            // a separate application service.

            if (service)
            {
                service->handle(subject, payload);
            }
        });

    /*
        If the message processing performs database work or expensive computation,
        use a dedicated worker queue rather than blocking Drogon’s event loop.
    */

    /*
        Then the plugin only handles NATS transport:
        This makes the command logic testable without starting NATS or Drogon.
    */

}
