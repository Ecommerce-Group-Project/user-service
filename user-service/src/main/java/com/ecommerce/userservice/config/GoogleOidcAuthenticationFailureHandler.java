package com.ecommerce.userservice.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class GoogleOidcAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Value("${frontend.redirect-url}")
    private String frontendRedirectUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        String errorMessage = exception.getMessage();
        String redirectUrl = frontendRedirectUrl + "?error=" +
                URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

        response.sendRedirect(redirectUrl);
    }
}