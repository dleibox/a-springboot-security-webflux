package a.springboot.security.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
@EnableWebFlux
public class CORSFilter implements WebFluxConfigurer {
	
	private static final Logger log = LoggerFactory.getLogger(CORSFilter.class);

	@Override
	public void addCorsMappings(CorsRegistry registry) {
		log.info("[-- {} --]", this.getClass().getSimpleName());
		registry.addMapping("/**").allowedOrigins("*").allowedMethods("*").allowedHeaders("*");
	}
}
