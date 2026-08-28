package com.ecommerce.userservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /**
     * Converts the raw secret string into a type-safe HMAC SecretKey.
     * Uses Keys.hmacShaKeyFor() to automatically validate key strength (>= 256 bits)
     * and select the appropriate HMAC-SHA algorithm (e.g., HS256) based on byte length.
     *
     * @return SecretKey used for signing and verifying JWT tokens
     */
    private SecretKey getSigningKey(){
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    public String generateToken(Long userId, String role){

        return Jwts.builder()
                .claims(Map.of(
                        "role",role
                ))
                .subject(userId.toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSigningKey())
                .compact();
    }


    public boolean validateToken(String token){
        try{

            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;

        }catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }



    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    public Long extractUserId(String token){
        return Long.parseLong(extractClaim(token, Claims::getSubject));
    }

    public String extractRole(String token){
        return extractAllClaims(token).get("role",String.class);
    }


    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }



}
