package org.pipesor.logevent.shared.security;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Fixed, detail-free {@code application/problem+json} bodies for 400 (malformed bearer), 401 and 403 (platform identity
 * contract v1, §9). Token validation details are never written to the response.
 */
public final class PlatformProblems {
    private PlatformProblems() { }

    public static AuthenticationEntryPoint unauthenticated() {
        return (request, response, failure) -> {
            // A malformed or repeated Authorization header is a bad request (RFC 6750 invalid_request), as in the reference.
            if (failure instanceof OAuth2AuthenticationException oauth
                    && "invalid_request".equals(oauth.getError().getErrorCode())) {
                write(response, 400, "Bad Request", "INVALID_REQUEST");
            } else {
                write(response, 401, "Unauthorized", "UNAUTHENTICATED");
            }
        };
    }

    public static AccessDeniedHandler denied() {
        return (request, response, failure) -> write(response, 403, "Forbidden", "CALLER_DENIED");
    }

    private static void write(HttpServletResponse response, int status, String title, String code) throws IOException {
        if (response.isCommitted()) return;
        response.resetBuffer();
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        if (status == 401) response.setHeader("WWW-Authenticate", "Bearer");
        response.setContentType("application/problem+json");
        byte[] body = ("{\"type\":\"about:blank\",\"title\":\"" + title + "\",\"status\":" + status
                + ",\"code\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8);
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
