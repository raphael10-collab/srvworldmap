#include "AuthFilter.h"
#include "../services/SessionService.h"

void AuthFilter::doFilter(const drogon::HttpRequestPtr& request, drogon::FilterCallback&& callback, drogon::FilterChainCallback&& chainCallback)
{
    if (!request)
    {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k401Unauthorized);
        callback(response);
        return;
    }
    SessionService service;
    const auto token = service.extractSessionToken(request);

    if (!token.has_value())
    {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(drogon::k401Unauthorized);
        response->addHeader("Cache-Control", "no-store");
        callback(response);
        return;
    }

    SessionService::validateAsync(
        token.value(),
        [request,
         callback = std::move(callback),
         chainCallback = std::move(chainCallback)](
            std::optional<AuthenticatedUser> user) mutable
        {
            if (!user.has_value())
            {
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k401Unauthorized);
                response->addHeader("Cache-Control", "no-store");
                callback(response);
                return;
            }

            if (!user->canViewRestrictedMap)
            {
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k403Forbidden);
                response->addHeader("Cache-Control", "no-store");
                callback(response);
                return;
            }
            request->attributes()->insert("user_id", user->id);

            chainCallback();
        });
}
