package com.sajotuna.gateway.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor

public class GuestCartIdHeaderFilter implements GlobalFilter , Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        String guestCartId = null;
        if (request.getCookies().containsKey("guestCartId")) {
            guestCartId = request.getCookies().getFirst("guestCartId").getValue();
        }

        if (guestCartId != null) {
            System.out.println(guestCartId);
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-Guest-Cart-Id", guestCartId)
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        }
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -10;
    }
}
