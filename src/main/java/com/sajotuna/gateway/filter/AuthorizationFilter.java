package com.sajotuna.gateway.filter;

import com.sajotuna.gateway.tokenParser.JwtTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationFilter implements GlobalFilter, Ordered {
    private final JwtTokenValidator jwtTokenValidator;

    private static final List<Pattern> BLACKLIST_PATTERNS = List.of(
            Pattern.compile("^/address.*$"),
            Pattern.compile("^/users/me$"),
            Pattern.compile("^/withdraw$")
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        boolean isBlackListed = BLACKLIST_PATTERNS.stream()
                .anyMatch(pattern -> pattern.matcher(path).matches());

        if (!isBlackListed) {
            log.info("[Whitelist] 인증 체크 제외: {}", path);
            return chain.filter(exchange);  // 인증 필터 적용 안함
        }

        ServerHttpRequest request = exchange.getRequest();

        String accessToken = null;
        if (request.getCookies().containsKey("access_token")) {
            accessToken = request.getCookies().getFirst("access_token").getValue();
        }

        String refreshToken = null;
        if (request.getCookies().containsKey("refresh_token")) {
            refreshToken = request.getCookies().getFirst("refresh_token").getValue();
        }


        if (!jwtTokenValidator.validate(accessToken)) {
            if(!jwtTokenValidator.validateRefreshToken(refreshToken)) {
                exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                exchange.getResponse().getHeaders().setLocation(URI.create("/login"));
                return exchange.getResponse().setComplete();
            }
            exchange.getResponse().setStatusCode(HttpStatus.FOUND);
            exchange.getResponse().getHeaders().setLocation(URI.create("/token/refresh"));
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
