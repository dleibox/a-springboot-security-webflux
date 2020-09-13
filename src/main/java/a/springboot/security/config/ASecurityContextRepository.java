package a.springboot.security.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class ASecurityContextRepository implements ServerSecurityContextRepository{
	
	private static final Logger log = LoggerFactory.getLogger(ASecurityContextRepository.class);
	
	@Autowired
	private AAuthenticationManager authenticationManager;

	@Override
	public Mono<Void> save(ServerWebExchange swe, SecurityContext sc) {
		throw new UnsupportedOperationException("Not supported yet.");
	}

	@Override
	public Mono<SecurityContext> load(ServerWebExchange swe) {
		log.info("[-- {} --] load: {}", this.getClass().getSimpleName(), swe.getClass().getSimpleName());

		ServerHttpRequest request = swe.getRequest();
		String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			String authToken = authHeader.substring(7);
			Authentication auth = new UsernamePasswordAuthenticationToken(authToken, authToken);
			return this.authenticationManager.authenticate(auth).map((authentication) -> {
				return new SecurityContextImpl(authentication);
			});
		} else {
			return Mono.empty();
		}
	}
	
}
