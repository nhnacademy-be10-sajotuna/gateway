package com.sajotuna.gateway.filter;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
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
public class NoAuthorizationFilter implements GlobalFilter, Ordered {

    private static final List<Pattern> BLACKLIST_PATTERNS = List.of(
            Pattern.compile("^/login$"),
            Pattern.compile("^/register$")
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        String userId = exchange.getRequest()
                .getHeaders()
                .getFirst("X-User-Id");

        boolean isBlackListed = BLACKLIST_PATTERNS.stream()
                .anyMatch(pattern -> pattern.matcher(path).matches());

        if (isBlackListed && userId != null) {
            exchange.getResponse().setStatusCode(HttpStatus.FOUND);
            exchange.getResponse().getHeaders().setLocation(URI.create("/"));
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
