package com.sajotuna.gateway.filter;

import com.sajotuna.gateway.tokenParser.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class AuthorizationHeaderFilter implements GlobalFilter, Ordered {
    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtTokenProvider jwtTokenProvider;
    private static final Long ACCESS_TOKEN_EXPIRES = 1800 * 1000L;
    private static final List<Pattern> WHITELIST_PATTERNS = List.of(
            Pattern.compile("^/account-api/api/users/login$"),
            Pattern.compile("^/account-api/api/users$"),
            Pattern.compile("^/actuator(/.*)?$")
    );
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        boolean isWhiteListed = WHITELIST_PATTERNS.stream()
                .anyMatch(pattern -> pattern.matcher(path).matches());

        if (isWhiteListed) {
            return chain.filter(exchange);
        }


        ServerHttpRequest request = exchange.getRequest();

        String accessToken = getTokenFromCookie(request, "access_token");

        String refreshToken = getTokenFromCookie(request, "refresh_token");

        if (accessToken != null && jwtTokenProvider.validate(accessToken)) {
            String userId = jwtTokenProvider.getIdFromToken(accessToken);
            String userRole = jwtTokenProvider.getRoleFromToken(accessToken);

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Id", userId)
                    .header("X-User-Role", userRole)
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        }

        if (refreshToken != null && jwtTokenProvider.validate(refreshToken)) {
            String userId = jwtTokenProvider.getIdFromToken(refreshToken);
            String userRole = jwtTokenProvider.getRoleFromToken(refreshToken);
            String email = jwtTokenProvider.getEmailFromToken(refreshToken);

            String storedRefreshToken = (String) redisTemplate.opsForValue().get("refresh_token:"+email);
            if (refreshToken.equals(storedRefreshToken)) {
                String newAccessToken = jwtTokenProvider.generateAccessToken(userId, email, userRole);

                ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", newAccessToken)
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .maxAge(ACCESS_TOKEN_EXPIRES)
                        .sameSite("Lax")
                        .build();

                exchange.getResponse().addCookie(accessTokenCookie);

                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Role", userRole)
                        .build();
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            }
        }
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private String getTokenFromCookie(ServerHttpRequest request, String name) {
        return request.getCookies().getFirst(name) != null
                ? request.getCookies().getFirst(name).getValue()
                : null;
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
