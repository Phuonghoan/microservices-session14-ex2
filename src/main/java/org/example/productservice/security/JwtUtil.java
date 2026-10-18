package org.example.productservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

@Component
public class JwtUtil {

    private final Key signingKey;

    public JwtUtil(
            @Value("${app.jwt.secret}") String jwtSecret
    ) {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);

        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public Claims extractClaims(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
