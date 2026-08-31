package com.ecommerce.userservice.config;

import com.ecommerce.userservice.util.JwtUtil;
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
import java.util.Collections;
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

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }


        if (jwtUtil.validateToken(token)) {
            Long  userId = jwtUtil.extractUserId(token);
            List<SimpleGrantedAuthority> authorities = jwtUtil.extractRoles(token).stream().map((role)->new SimpleGrantedAuthority(role)).toList();

            if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Attach the email and authorities to Spring's SecurityContext

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId,
                        null,
                        authorities
                );

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }



}