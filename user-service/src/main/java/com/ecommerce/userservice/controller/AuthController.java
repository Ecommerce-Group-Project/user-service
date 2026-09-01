package com.ecommerce.userservice.controller;


import com.ecommerce.userservice.dto.AuthResponse;
import com.ecommerce.userservice.dto.CurrentUser;
import com.ecommerce.userservice.dto.LoginRequest;
import com.ecommerce.userservice.dto.RegisterRequest;
import com.ecommerce.userservice.entity.User;
import com.ecommerce.userservice.service.AuthCookieService;
import com.ecommerce.userservice.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthCookieService authCookieService;


    @Autowired
    public AuthController(AuthService authService,AuthCookieService authCookieService){
        this.authService = authService;
        this.authCookieService = authCookieService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request));
    }


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        Map<String,Object> loginResult = authService.login(request);

        User user = (User) loginResult.get("user");
        String token = (String) loginResult.get("token");

        AuthResponse authResponse = AuthResponse
                .builder()
                .id(user.getId())
                .name(user.getName())
                .roles(user.getRoles())
                .email(user.getEmail())
                .build();

        ResponseCookie authCookie = authCookieService.createAccessCookie(token);

        return  ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,authCookie.toString())
                .body(authResponse);


    }

    @GetMapping("/me")
    public ResponseEntity<AuthResponse> me(@AuthenticationPrincipal CurrentUser currentUser){
        if(currentUser == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        AuthResponse authResponse = AuthResponse.builder()
                .id(currentUser.getId())
                .name(currentUser.getName())
                .email(currentUser.getEmail())
                .roles(currentUser.getRoles())
                .build();

        return ResponseEntity.ok(authResponse);

    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(){
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE,authCookieService.clear().toString()).build();
    }

}
