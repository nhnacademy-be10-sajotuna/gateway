package com.sajotuna.gateway.tokenParser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class JwtTokenValidator {
    private final RedisTemplate<String, Object> redisTemplate;
    private final Environment env;
    private byte[] secretKey;

    public JwtTokenValidator(Environment env, RedisTemplate<String, Object> redisTemplate) {
        this.env = env;
        this.redisTemplate = redisTemplate;
        secretKey = env.getProperty("token.secret").getBytes(StandardCharsets.UTF_8);
    }

    public boolean validateRefreshToken(String refreshToken) {
        if (refreshToken == null) {
            return false;
        }
        String email = getEmailFromToken(refreshToken);
        String savedRefreshToken = (String) redisTemplate.opsForValue().get("refresh_token:" + email);
        if (!refreshToken.equals(savedRefreshToken)) {
            return false;
        }
        return validate(refreshToken);
    }

    public boolean validate(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("email", String.class);
    }

    public String getRoleFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.get("role", String.class);
    }

    public String getIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

}
