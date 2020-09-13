package a.springboot.security.config;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import a.springboot.security.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class AAuthenticationManager implements ReactiveAuthenticationManager {
	
	private static final Logger log = LoggerFactory.getLogger(AAuthenticationManager.class);

	@Autowired
	@Qualifier("JwtRsa")
	private JwtUtil jwtUtil;
	
	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		log.info("[---] authentication: {}", authentication);
		
		String authToken = authentication.getCredentials().toString();

		try {
			if (!jwtUtil.validateToken(authToken)) {
				return Mono.empty();
			}
			Claims claims = jwtUtil.getAllClaimsFromToken(authToken);
			List<GrantedAuthority> authorities = new ArrayList<>();
			List<String> rolesMap = claims.get("role", List.class);
			rolesMap.forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
			return Mono.just(new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities));
		} catch (Exception e) {
			log.info("[---]ERR authentication: {}", e.getMessage());
			return Mono.empty();
		}
	}
}