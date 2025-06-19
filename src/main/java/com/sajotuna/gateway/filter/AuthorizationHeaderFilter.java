package com.sajotuna.gateway.filter;

import com.sajotuna.gateway.tokenParser.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
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
@Slf4j
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

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        log.info("Authorization header: {}", authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }


        String accessToken = authHeader.substring(7);

        if (jwtTokenProvider.validate(accessToken)) {
            String userId = jwtTokenProvider.getIdFromToken(accessToken);
            String userRole = jwtTokenProvider.getRoleFromToken(accessToken);

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Id", userId)
                    .header("X-User-Role", userRole)
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        }

        return unauthorized(exchange);
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
