#pragma once

#include <drogon/drogon.h>

class AuthFilter : public drogon::HttpFilter<AuthFilter>
{
    public:
        void doFilter(const drogon::HttpRequestPtr& request, drogon::FilterCallback&& callback, drogon::FilterChainCallback&& chainCallback) override;
};
