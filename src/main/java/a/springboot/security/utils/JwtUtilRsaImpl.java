package a.springboot.security.utils;

import java.security.KeyFactory;
import java.security.KeyPair;
//import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.impl.crypto.RsaProvider;

@Service
@Qualifier("JwtRsa")
public class JwtUtilRsaImpl implements JwtUtil {
	
	private static final Logger log = LoggerFactory.getLogger(JwtUtilRsaImpl.class);

	@Value("${app.jjwt.issuer}")
	private String issuer;

	@Value("${app.jjwt.expiration}")
	private String expirationTime;

	private String privateKey = "----BEGIN PRIVATE KEY-----\r\n"
			+ "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCy6dYkbIQrC/FB\r\n"
			+ "LadjkUDBFkxslapC3KAFrN7oWlkUcon9TA3J8k9hL4IxlLLLcAipbr0NCAm1cl+q\r\n"
			+ "M14SGboapqwMmr/uRuEujiZrUW9txHUk0Lk+N0d8FfVETmbgxmMZP+5SWY6qvqtk\r\n"
			+ "ddNpJfxqVvjuayFVBhjsxamSLg1cowRTGKU28/f31y2aJb/wDuVXMSk0RHWY6FhG\r\n"
			+ "23iedTJb8dG5QbMdhxPgC9eFb0XkeZd5xIe476Atg3wkFP6e18Qh/9gRsdKzE3s4\r\n"
			+ "ziB30mIAjjxDNYg03sZQx++2g5Ii1P497OqSU33PUiCEEzq7aXGTHcjTPKkEnwWF\r\n"
			+ "gMBpiuTfAgMBAAECggEBAIJLqZh9LwPqfphpFy576hy0kJPDq2tmIWQAsZWltpod\r\n"
			+ "kEDX0nLv9L9iSf6xvERMIwLBkwyaffeWg/T/09J6yf3+w+2qBX0SQYwWGgSuGehm\r\n"
			+ "2qklGMMmnvjPRP+p2WJ5GFKbLITsk+nlUgyngn9hGqKXFFMN0giJmD1W9ldvEmwT\r\n"
			+ "VHdetKpwq8RA7lUVX5BvJYgQXdM7xK6oIV2EwRotTsIyGIb3+GYpL32leHlEcauW\r\n"
			+ "3mZ0ffUppKa/BmmfvhIfaP8uVjgrvsHLR4K4MWtmmbsFK/U6p1jgWFY0o8cGqMBb\r\n"
			+ "CtDjEuDiO75KLUqC9cSELyHCjDOLDQARG4m1XytUmYECgYEA3dIu6Gc5MASJAQ/x\r\n"
			+ "0XId7lel+lDS3AgLdV0OodxAWv8yuw/5q80Pq4L96y4weCZ8ucE01PxG75/eiMoE\r\n"
			+ "H5DSw+C3Osa3HBqMAHBVBOngP7y/Ue6n3218vtW1xdAGYJg05WCTc1Yk8byp1FFh\r\n"
			+ "hRplShFnXmwpK8YFkXZ4HAj/BSMCgYEAznslZ0k4uyMJ7vmTrnB5eM3+fkCXqUz/\r\n"
			+ "INhCl0IAGZ4i7NGHMfoJnTEWjuPVna7Wc32WdEtWFBocgzmX0weusU75t5rH9OoB\r\n"
			+ "CUEjGBo3yrhbc1QWu0wE0pSpUwf9EOR1TIzGsagzivRU0Z9XKxNyPcm0y8Z3+ysK\r\n"
			+ "7jU394hYsxUCgYAKvHWQwg4+iLmo14C4xnE0bAGYj/jktW74izx+EQ78WIW4EBnh\r\n"
			+ "etdbUcfAbkfiSNqYkwVfmaZFStOWg1CXxoas/F9h9OQ/8/j6vHUg+8Di1Nvdt1Ng\r\n"
			+ "uQfkpKtbm6nzWuqUf4wjdPPsz1jY8edqbdChOR5rr4h+meMDG1zM3pKZSQKBgFzo\r\n"
			+ "encUMmu6I3Edaf826uGZxyamB9gNJktwI96Nux/L0SlASpYJTSQm/2CCUg9mqWZE\r\n"
			+ "H1vqvivDaAr/8jnpngh4YdLk2Y5xcM/qOFFTEsGr3LJzJttWJGFgtSQAVzWvprww\r\n"
			+ "KAOujKq8sCG2kfF3CZOV3D1I65nfz0ZKOgmul0LVAoGBANhNg8Oy2nOHpK77gG70\r\n"
			+ "QWGm0EyWNJtroduKy4IJ8oO3F3OhQKpfh//+W/ifV7XiXDMNMnOlwjMBEcqSE/+B\r\n"
			+ "1vzO3qIzSbj6cME/ZVTmAsEUX4RuzPxIeKIO0BYqJDrN/zACVzXJfAuED3Lc+Dbi\r\n"
			+ "R+pC6hFD5RyIaZJEzGysIlUt\r\n"
			+ "-----END PRIVATE KEY-----";

	private String publicKey = "-----BEGIN PUBLIC KEY-----\r\n"
			+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsunWJGyEKwvxQS2nY5FA\r\n"
			+ "wRZMbJWqQtygBaze6FpZFHKJ/UwNyfJPYS+CMZSyy3AIqW69DQgJtXJfqjNeEhm6\r\n"
			+ "GqasDJq/7kbhLo4ma1FvbcR1JNC5PjdHfBX1RE5m4MZjGT/uUlmOqr6rZHXTaSX8\r\n"
			+ "alb47mshVQYY7MWpki4NXKMEUxilNvP399ctmiW/8A7lVzEpNER1mOhYRtt4nnUy\r\n"
			+ "W/HRuUGzHYcT4AvXhW9F5HmXecSHuO+gLYN8JBT+ntfEIf/YEbHSsxN7OM4gd9Ji\r\n"
			+ "AI48QzWINN7GUMfvtoOSItT+PezqklN9z1IghBM6u2lxkx3I0zypBJ8FhYDAaYrk\r\n"
			+ "3wIDAQAB\r\n"
			+ "-----END PUBLIC KEY-----";

	private KeyPair keyPair;

	@PostConstruct
	public void init() throws NoSuchAlgorithmException, InvalidKeySpecException {
		log.info("[---] init: post construct");
		
		// version 1:
//		keyPair = RsaProvider.generateKeyPair(2048); // Keys.keyPairFor(SignatureAlgorithm.RS256);

		// version 2:
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//		kpg.initialize(2048); // RSA256
//		keyPair = kpg.generateKeyPair();
//		PrivateKey prv = keyPair.getPrivate();
//		PublicKey pub = keyPair.getPublic();

		// version 3:
		// unencrypted PKCS#1 using '-----BEGIN RSA PRIVATE KEY-----'
		// unencrypted PKCS#8 using '-----BEGIN PRIVATE KEY-----'
		String key = privateKey.replace("----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
				.replaceAll("\r\n", "");
		byte[] keyBytes = Base64.getDecoder().decode(key);
		PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(keyBytes); // PKCS#8
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey prv = kf.generatePrivate(pkcs8);

		key = publicKey.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\r\n", "");
		keyBytes = Base64.getDecoder().decode(key);
		X509EncodedKeySpec x509 = new X509EncodedKeySpec(keyBytes);
		PublicKey pub = kf.generatePublic(x509);

		keyPair = new KeyPair(pub, prv);

		log.info("\r\n\r\nPrivate Key: {}\r\n", Base64.getEncoder().encodeToString(prv.getEncoded()));
		log.info("\r\n\r\nPublic Key: {}\r\n", Base64.getEncoder().encodeToString(pub.getEncoded()));
	}

	@Override
	public Claims getAllClaimsFromToken(String token) {
		return Jwts.parserBuilder().setSigningKey(keyPair.getPublic()).build().parseClaimsJws(token).getBody();
	}

	@Override
	public String getUsernameFromToken(String token) {
		return getAllClaimsFromToken(token).getSubject();
	}

	@Override
	public Date getExpirationDateFromToken(String token) {
		return getAllClaimsFromToken(token).getExpiration();
	}

	@Override
	public String generateToken(UserDetails user) {
		log.info("[---] userDetails: {}", user);
		Map<String, Object> claims = new HashMap<>();
		claims.put("role", user.getAuthorities().stream().map(a -> a.getAuthority()).toArray()); // ..getRoles());
		// NOTE: Calling setClaims will overwrite any existing claim name/value pairs
		// with the same names that might have already been set.
		return Jwts.builder().setClaims(claims).setSubject(user.getUsername()).setIssuer(issuer)
				.setId(UUID.randomUUID().toString()).setIssuedAt(Date.from(Instant.now()))
				.setExpiration(Date.from(Instant.now().plus(Duration.ofSeconds(Long.parseLong(expirationTime)))))
				.signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256).compact();
	}

	@Override
	public Boolean validateToken(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return !expiration.before(new Date());
	}

}
