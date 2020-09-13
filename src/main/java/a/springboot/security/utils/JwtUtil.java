package a.springboot.security.utils;

import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.Claims;

public interface JwtUtil {
	Claims getAllClaimsFromToken(String token);

	String getUsernameFromToken(String token);

	Date getExpirationDateFromToken(String token);

	String generateToken(UserDetails user);

	Boolean validateToken(String token);
}
