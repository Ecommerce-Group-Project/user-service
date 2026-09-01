package com.ecommerce.userservice.config;

import com.ecommerce.userservice.dto.CurrentUser;
import com.ecommerce.userservice.entity.Role;
import com.ecommerce.userservice.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${access-token.cookie-name}")
    private String AUTH_COOKIE_NAME;

    private final JwtUtil jwtUtil;


    @Autowired
    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    private String getTokenFromCookie(HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies !=null){
            for(Cookie cookie:cookies){
                if(cookie.getName().equals(AUTH_COOKIE_NAME)){
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {



        String token = getTokenFromCookie(request);

        if (token == null || SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try{
            if (jwtUtil.validateToken(token)) {


                //Create an object name CurrentUser for AuthenticationPrincipal & Set it to SecurityContextHolder
                List<String> roles = jwtUtil.extractRoles(token);

                //AuthenticationPrincipal
                CurrentUser currentUser = CurrentUser.builder()
                        .id(jwtUtil.extractUserId(token))
                        .email(jwtUtil.extractUserEmail(token))
                        .name(jwtUtil.extractUserName(token))
                        .roles(roles.stream().map((role)-> Role.valueOf(role)).toList())
                        .build();

                List<SimpleGrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).toList();


                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        currentUser, //AuthenticationPrincipal
                        null,
                        authorities
                );

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        }catch (JwtException | IllegalArgumentException e){
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    }


