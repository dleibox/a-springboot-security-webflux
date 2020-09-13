package a.springboot.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ASpringbootSecurityApplication {
	
	private static final Logger log = LoggerFactory.getLogger(ASpringbootSecurityApplication.class);

	public static void main(String[] args) {
		log.info("[-- {} --] main: {}", ASpringbootSecurityApplication.class.getSimpleName(), args);
		
		SpringApplication.run(ASpringbootSecurityApplication.class, args);
	}

}
