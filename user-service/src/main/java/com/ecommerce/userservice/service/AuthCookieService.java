package com.ecommerce.userservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class AuthCookieService {
    @Value("${access-token.cookie-name}")
    private String AUTH_COOKIE_NAME;

    @Value("${access-token.ttl-ms}")
    private long accessTtlMs;

    @Value("${access-token.cookie-secure}")
    private boolean accessSecure;


    @Value("${refresh-token.cookie-name}")
    private String REFRESH_COOKIE_NAME;

    @Value("${refresh-token.ttl-ms}")
    private long refreshTtlMs;

    @Value("${refresh-token.cookie-secure}")
    private boolean refreshSecure;


    public ResponseCookie createAccessCookie(String accessToken){
        return ResponseCookie.from(AUTH_COOKIE_NAME,accessToken)
                .httpOnly(true)
                .sameSite("Lax")
                .path("/")
                .secure(accessSecure)
                .maxAge(accessTtlMs)
                .build();
    }


    public ResponseCookie createRefreshCookie(String refreshToken){
        return ResponseCookie.from(REFRESH_COOKIE_NAME,refreshToken)
                .httpOnly(true)
                .sameSite("Lax")
                .path("/")
                .secure(refreshSecure)
                .maxAge(Duration.ofMillis(refreshTtlMs))
                .build();
    }

    public ResponseCookie clear() {
        return ResponseCookie.from(AUTH_COOKIE_NAME,"")
                .httpOnly(true)
                .secure(accessSecure)
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
    }

}
