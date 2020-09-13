package a.springboot.security;

import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class ASpringbootSecurityApplication {

	private static final Logger log = LoggerFactory.getLogger(ASpringbootSecurityApplication.class);

	public static void main(String[] args) {
		log.info("[---] main: {}", args);

		SpringApplication.run(ASpringbootSecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
		return args -> {
			StringBuilder sb = new StringBuilder();
			sb.append("The beans provided by Spring Boot:");
			String[] beanNames = ctx.getBeanDefinitionNames();
			Arrays.sort(beanNames);
			for (String beanName : beanNames) {
				sb.append("\r\n[");
				sb.append(beanName);
				sb.append("]");
			}
			sb.append("\r\n");
			log.info(sb.toString());
		};
	}
}
