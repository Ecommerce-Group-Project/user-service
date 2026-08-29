package com.ecommerce.userservice.config;


import com.ecommerce.userservice.entity.User;
import com.ecommerce.userservice.repository.UserRepository;
import com.ecommerce.userservice.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${frontend.redirect-url")
    private String frontendRedirectUrl;

    @Autowired
    public GoogleOidcAuthenticationSuccessHandler(UserRepository userRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public 	void onAuthenticationSuccess(HttpServletRequest request,
                                           HttpServletResponse response,

                                           Authentication authentication) throws IOException, ServletException{

        // 1. Because we used the "openid" scope, Spring returns an OidcUser, not a generic OAuth2User.
        // By the time this code runs, Spring has ALREADY verified the signature using Google's public keys.
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

        OidcIdToken idToken = oidcUser.getIdToken();
        String email = idToken.getEmail();

        User user = userRepository.findByEmail(email).orElseGet(()->{
            User newUser = User.builder()
                    .email(email)
                    .build();
            return userRepository.save(newUser);
        });

        String appJwtToken = jwtUtil.generateToken(user.getId(), user.getRole().name());

        response.sendRedirect(frontendRedirectUrl+"?token="+appJwtToken);








    }

}
