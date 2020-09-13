package a.springboot.security.utils;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
//import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
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

	private static final String PKCS_1_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"; // unencrypted
	private static final String PKCS_1_PEM_FOOTER = "-----END RSA PRIVATE KEY-----"; // unencrypted
	private static final String PKCS_8_PEM_HEADER = "-----BEGIN PRIVATE KEY-----"; // unencrypted
	private static final String PKCS_8_PEM_FOOTER = "-----END PRIVATE KEY-----"; // unencrypted
	private static final String X509_PEM_HEADER = "-----BEGIN PUBLIC KEY-----"; // unencrypted
	private static final String X509_PEM_FOOTER = "-----END PUBLIC KEY-----"; // unencrypted

	@Value("${app.jjwt.issuer}")
	private String issuer;

	@Value("${app.jjwt.expiration}")
	private String expirationTime;

//	https://www.devglan.com/online-tools/rsa-encryption-decryption
//	https://decoder.link/rsa_converter
	private String privateKey = "-----BEGIN RSA PRIVATE KEY-----\r\n"
			+ "MIIEpQIBAAKCAQEA22PDae0KF65OO2VSRNDAzhm+x8Wl1DiaX9qThJsG2RSYCKCk\r\n"
			+ "WzaJhrRZuW73gZvuLqvZwfYU/ROFFvH3E2ySEdjF81HHjJJBFZaKfPI4mcF0BFx2\r\n"
			+ "sQz7riTfhCmK6xqChZlZ+SlKJgKxrWUHNtGtN+KtQ9b2dPx88x9EDUMqMXdCWYbb\r\n"
			+ "uomLzL90IAtKW12J8bsP62fUW562aZa8ovEEIMUozBGfGqZ5dS0HQcfwdBgHfgvC\r\n"
			+ "dQ9XVcOgvN0DtRoTGao3dQhKbwY0fBXCFIHfxNM4Rjtplt6PRVjn/Jt/SXz9uPrk\r\n"
			+ "UsPcEKfw5xBXA1mM8niKDsMgaX9FlKtPHB+xxQIDAQABAoIBAHOxKFuzpJ7YTGkG\r\n"
			+ "BVxEuWf2K6UtlUVUlBP4L9K97d6L/aCPFh0DpYJjmO0wl1TB5di2xx6Bpo/Ou2Be\r\n"
			+ "OO0FVAIVTk4B0jlO5wN7X4yEL1Tlr0idefnj3tT2nOgVACz6zdmmBMxf+boRsaC+\r\n"
			+ "pg9CgxX1c2lS8qS+gSW0Vy6nPJjYULjDh8JK2SX3jOAuJ7RRAaeU3ty5tDdHDB8I\r\n"
			+ "YCes/8q6h3k4J3WCWVecsia1a34hrqwja96KpupWXiXSJ1HATm1ZFr3iYUjpkr4+\r\n"
			+ "F5iS6t4bkTRq5WaxebSeRmCAX6jzzg50qrmoGZdhc180EEifZzkYNcXHTrczkYPj\r\n"
			+ "X313wAECgYEA/AaWuRP2eHIykFmRiWoaoJf+feSsbjNnYOfVOiL//bstIxke6Q61\r\n"
			+ "PKgQkUNXMrdN9xd16VM3y0Aqi9b5ukCNQ9lgIuxmuqGwEjvs41vUw8FuWnHldaVq\r\n"
			+ "L3t8/Smec4B3Tjn9xql6LHOCt0e6opZf7KLUtMWWNdPQOUXYzfF3IfUCgYEA3tls\r\n"
			+ "0B5gntgOaNB3zIn3m6hEG51OPIzBQ68dfHR3XqLKnQT3NbVZ5dp1g7eCnwPNhlfB\r\n"
			+ "SP/HY2VDNhyFzAikRmEujbn8WmKW4IiReoYcBGukhBxshGfNu/NmYkzGhr0Gs0Wb\r\n"
			+ "CHV5bMXz13v2EGuseMgPGc3wFUMtj7CQWKCH3pECgYEA6aTeFITaSX1tPP+cee1g\r\n"
			+ "9CMU7veRl7SWEXO77OLHuh3N0a0XR+63vJz+hv0MGNtxLzKTwJTCs+4vw2awK6hu\r\n"
			+ "jkk25AmPj1QYXD8r9PeMf1KTEMxocrHAiHaOQFFWMTQW5vHCQGub9Ru9QlcAQnzw\r\n"
			+ "PvwR/+jxwcM1VfNX9Ez4KgUCgYEApRBJT/JgQOfp7GsVgVRkKlC9efLPg3wCnv6z\r\n"
			+ "iX6++EL+bsXB0m9skht5VcH0p5HqhuqzST3j01SrLwZ7eECiZVsQX3v2VoCWHuQp\r\n"
			+ "VabGU+PjbNOc8Ynt0pycJo2VszGKJ/mTtvVEpnQNhHvWLB2FF8Wfoc5vWWBz++2d\r\n"
			+ "TXhCi3ECgYEAy7SFVmnMS8QRT0HApfq0IVUL6NrLi3vIbXErm+8RLSqu7WBq9uP4\r\n"
			+ "EEAdUDVSiOKNPXi6t9c9bUwFcm+q93SWtalAIPetb2lRtKJXu2GbGpw3I0oOMjjt\r\n"
			+ "TPIpQyrouYM6YRoos+Fxohe1iJ0G4GtxKbi3Qv2QNhBSL3/CUCXpHyY=\r\n"
			+ "-----END RSA PRIVATE KEY-----";

	private String publicKey = "-----BEGIN PUBLIC KEY-----\r\n"
			+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA22PDae0KF65OO2VSRNDA\r\n"
			+ "zhm+x8Wl1DiaX9qThJsG2RSYCKCkWzaJhrRZuW73gZvuLqvZwfYU/ROFFvH3E2yS\r\n"
			+ "EdjF81HHjJJBFZaKfPI4mcF0BFx2sQz7riTfhCmK6xqChZlZ+SlKJgKxrWUHNtGt\r\n"
			+ "N+KtQ9b2dPx88x9EDUMqMXdCWYbbuomLzL90IAtKW12J8bsP62fUW562aZa8ovEE\r\n"
			+ "IMUozBGfGqZ5dS0HQcfwdBgHfgvCdQ9XVcOgvN0DtRoTGao3dQhKbwY0fBXCFIHf\r\n"
			+ "xNM4Rjtplt6PRVjn/Jt/SXz9uPrkUsPcEKfw5xBXA1mM8niKDsMgaX9FlKtPHB+x\r\n"
			+ "xQIDAQAB\r\n"
			+ "-----END PUBLIC KEY-----";

	private KeyPair keyPair;

	@PostConstruct
	public void init() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		log.info("[---] init: post construct");
		log.info("[---] privateKey:\r\n{}\r\n", privateKey);
		log.info("[---] publicKey:\r\n{}\r\n", publicKey);

//		version 1:
//		keyPair = RsaProvider.generateKeyPair(2048); // Keys.keyPairFor(SignatureAlgorithm.RS256);

//		version 2:
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//		kpg.initialize(2048); // RSA256
//		keyPair = kpg.generateKeyPair();
//		PrivateKey prv = keyPair.getPrivate();
//		PublicKey pub = keyPair.getPublic();

//		version 3:
		byte[] keyBytes;
		KeySpec keySpec;
		if (privateKey.contains(PKCS_1_PEM_HEADER)) {
			String key = privateKey.replace(PKCS_1_PEM_HEADER, "").replace(PKCS_1_PEM_FOOTER, "").replaceAll("\r\n",
					"");
			log.info("[---] {}", key);
			byte[] pkcs1 = Base64.getDecoder().decode(key);

//			version 1:
			RSAPrivateKey pk = RSAPrivateKey.getInstance(pkcs1); // and ASN1Sequence.fromByteArray(pkcs1) also works
			keySpec = new RSAPrivateKeySpec(pk.getModulus(), pk.getPrivateExponent());

//			version 2: without bouncycastle
//			https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
//			int pkcs1Length = pkcs1.length;
//			int totalLength = pkcs1Length + 22;
//			byte[] pkcs8Header = new byte[] { 0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff),
//					(byte) (totalLength & 0xff), // Sequence + total length
//					0x2, 0x1, 0x0, // Integer (0)
//					0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5,
//					0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
//					0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet
//																										// string +
//																										// length
//			};
//			keyBytes = new byte[pkcs8Header.length + pkcs1Length];
//			System.arraycopy(pkcs8Header, 0, keyBytes, 0, pkcs8Header.length);
//			System.arraycopy(pkcs1, 0, keyBytes, pkcs8Header.length, pkcs1Length);
//			keySpec = new PKCS8EncodedKeySpec(keyBytes); // PKCS#8
		} else {
			String key = privateKey.replace(PKCS_8_PEM_HEADER, "").replace(PKCS_8_PEM_FOOTER, "").replaceAll("\r\n",
					"");
			log.info("[---] {}", key);
			keyBytes = Base64.getDecoder().decode(key);
			keySpec = new PKCS8EncodedKeySpec(keyBytes); // PKCS#8
		}
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey prv = kf.generatePrivate(keySpec);

		keyBytes = Base64.getDecoder()
				.decode(publicKey.replace(X509_PEM_HEADER, "").replace(X509_PEM_FOOTER, "").replaceAll("\r\n", ""));
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

//Public key formats supported
//- PKCS#1 RSAPublicKey* (PEM header: BEGIN RSA PUBLIC KEY)
//- X.509 SubjectPublicKeyInfo** (PEM header: BEGIN PUBLIC KEY)
//- XML <RSAKeyValue>
//
//Encrypted private key format supported
//- PKCS#8 EncryptedPrivateKeyInfo** (PEM header: BEGIN ENCRYPTED PRIVATE KEY)
//
//Private key formats supported (unencrypted)
//- PKCS#1 RSAPrivateKey** (PEM header: BEGIN RSA PRIVATE KEY)
//- PKCS#8 PrivateKeyInfo* (PEM header: BEGIN PRIVATE KEY)
//- XML <RSAKeyPair> and <RSAKeyValue>
