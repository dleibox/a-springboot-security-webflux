package a.springboot.security.utils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
@Qualifier("JwtHmac")
public class JwtUtilHmacImpl implements JwtUtil {

	private static final Logger log = LoggerFactory.getLogger(JwtUtilHmacImpl.class);

	@Value("${app.jjwt.secret}")
	private String secret;

	@Value("${app.jjwt.expiration}")
	private String expirationTime;

	private Key key;

	@PostConstruct
	public void init() {
		log.info("[---] init: post construct");
		this.key = Keys.hmacShaKeyFor(secret.getBytes());
	}

	@Override
	public Claims getAllClaimsFromToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	@Override
	public String generateToken(UserDetails user) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("role", user.getAuthorities().stream().map(a->a.getAuthority()).toArray()); // .getRoles());
		return doGenerateToken(claims, user.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String username) {
		Long expirationTimeLong = Long.parseLong(expirationTime); // in second

		final Date createdDate = new Date();
		final Date expirationDate = new Date(createdDate.getTime() + expirationTimeLong * 1000);

		return Jwts.builder().setClaims(claims).setSubject(username).setIssuedAt(createdDate)
				.setExpiration(expirationDate).signWith(key).compact();
	}

	@Override
	public Boolean validateToken(String token) {
		return !isTokenExpired(token);
	}

}
