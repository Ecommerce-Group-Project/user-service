package com.ecommerce.userservice.config;


import com.ecommerce.userservice.entity.AuthProvider;
import com.ecommerce.userservice.entity.User;
import com.ecommerce.userservice.repository.UserRepository;
import com.ecommerce.userservice.service.AuthCookieService;
import com.ecommerce.userservice.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class GoogleOidcAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final AuthCookieService authCookieService;

    @Value("${frontend.success-redirect-url}")
    private String frontendRedirectUrl;

    @Autowired
    public GoogleOidcAuthenticationSuccessHandler(UserRepository userRepository, JwtUtil jwtUtil, AuthCookieService authCookieService) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.authCookieService = authCookieService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,

                                        Authentication authentication) throws IOException, ServletException {

        // 1. Because we used the "openid" scope, Spring returns an OidcUser, not a generic OAuth2User.
        // By the time this code runs, Spring has ALREADY verified the signature using Google's public keys.
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

        OidcIdToken idToken = oidcUser.getIdToken();
        String email = idToken.getEmail();
        String name = idToken.getClaim("name");

        User user = userRepository.findByEmail(email).orElseGet(() -> {
            User newUser = User.builder()
                    .name(name)
                    .email(email)
                    .authProvider(AuthProvider.GOOGLE)
                    .build();
            return userRepository.save(newUser);
        });

        String appAccessToken = jwtUtil.generateToken(user.getId(), user.getName(), user.getEmail(), user.getRoles());
        ResponseCookie authCookie = authCookieService.createAccessCookie(appAccessToken);

        response.addHeader("Set-Cookie", authCookie.toString());
        response.sendRedirect(frontendRedirectUrl);


    }

}
