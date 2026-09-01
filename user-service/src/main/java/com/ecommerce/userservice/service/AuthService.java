package com.ecommerce.userservice.service;


import com.ecommerce.userservice.dto.LoginRequest;
import com.ecommerce.userservice.dto.RegisterRequest;
import com.ecommerce.userservice.entity.User;
import com.ecommerce.userservice.exception.UserAlreadyExistsException;
import com.ecommerce.userservice.repository.UserRepository;
import com.ecommerce.userservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthService {

    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;


    @Autowired
    public AuthService(JwtUtil jwtUtil, PasswordEncoder passwordEncoder, UserRepository userRepository, AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    public String register(RegisterRequest registerRequest){
        if(userRepository.existsByEmail(registerRequest.getEmail())){
            throw new UserAlreadyExistsException("User with email: " + registerRequest.getEmail() + " already exists");
        }

        User user = User.builder()
                .name(registerRequest.getName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .build();

        userRepository.save(user);

        return "User registered successfully";
    }

    public Map<String,Object> login(LoginRequest loginRequest){
        // 1. The Bouncer: This single line calls CustomUserDetailsService.loadUserByUsername, checks the password hash,
        //    and verifies the account isn't locked. If it fails, it throws a BadCredentialsException.
           Authentication authentication = authenticationManager.authenticate(
                   new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
           );

        // 2. If we reach this line, the user is 100% authenticated.
        // We just fetch the user from the DB one more time to grab their ID and Role for the JWT payload.
           User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(()-> new UsernameNotFoundException("User not found"));

           String token = jwtUtil.generateToken(user.getId(), user.getName(),user.getEmail(),user.getRoles());

           return Map.of("token", token,"user",user);
    }


}
