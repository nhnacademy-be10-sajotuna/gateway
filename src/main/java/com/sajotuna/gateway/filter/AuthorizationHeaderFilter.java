package com.sajotuna.gateway.filter;


import com.sajotuna.gateway.tokenParser.JwtTokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationHeaderFilter implements GlobalFilter, Ordered {
    private final JwtTokenValidator jwtTokenValidator;
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();


        String accessToken = null;
        if (request.getCookies().containsKey("access_token")) {
            accessToken = request.getCookies().getFirst("access_token").getValue();
        }

        if (jwtTokenValidator.validate(accessToken)) {
            String userId = jwtTokenValidator.getIdFromToken(accessToken);
            String userRole = jwtTokenValidator.getRoleFromToken(accessToken);

            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Id", userId)
                    .header("X-User-Role", userRole)
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
