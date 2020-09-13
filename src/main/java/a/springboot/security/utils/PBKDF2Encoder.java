package a.springboot.security.utils;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PBKDF2Encoder implements PasswordEncoder {
	
	private static final Logger log = LoggerFactory.getLogger(PBKDF2Encoder.class);

	@Value("${app.password.encoder.salt}")
	private String salt;

	@Value("${app.password.encoder.iteration}")
	private Integer iteration;

	@Value("${app.password.encoder.keylength}")
	private Integer keylength;

	/**
	 * More info (https://www.owasp.org/index.php/Hashing_Java)
	 * 
	 * @param cs password
	 * @return encoded password
	 */
	@Override
	public String encode(CharSequence cs) {
		log.info("[---] encode: {}", cs);
		try {
			byte[] result = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
					.generateSecret(
							new PBEKeySpec(cs.toString().toCharArray(), salt.getBytes(), iteration, keylength))
					.getEncoded();
			return Base64.getEncoder().encodeToString(result);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
			throw new RuntimeException(ex);
		}
	}

	@Override
	public boolean matches(CharSequence cs, String string) {
		return encode(cs).equals(string);
	}

}
