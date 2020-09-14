package a.springboot.security.utils;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;

public interface JwtUtil {
	Claims getAllClaimsFromToken(String token);

	default String getSubjectFromToken(String token) {
		return getAllClaimsFromToken(token).getSubject();
	}

	default Date getExpirationDateFromToken(String token) {
		return getAllClaimsFromToken(token).getExpiration();
	}

	String generateToken(UserDetails user);

	Boolean validateToken(String token);
}