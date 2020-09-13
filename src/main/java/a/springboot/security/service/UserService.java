package a.springboot.security.service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import a.springboot.security.ASpringbootSecurityApplication;
import a.springboot.security.constant.Role;
import a.springboot.security.model.User;
import reactor.core.publisher.Mono;

@Service
public class UserService {

	private static final Logger log = LoggerFactory.getLogger(UserService.class);

	// this is just an example, you can load the user from the database from the
	// repository

	private Map<String, User> data;

	@PostConstruct
	public void init() {
		log.info("[-- {} --] init: ", this.getClass().getSimpleName(), "post construct");

		data = new HashMap<>();

		// username:passwowrd -> user:user
		data.put("user",
				new User("user", "CbvAjgLgyrUdZ6LCDtMC5zeixFqLEFV/Sl4W6Y9606w=", true, Arrays.asList(Role.ROLE_USER)));

		// username:passwowrd -> admin:admin
		data.put("admin", new User("admin", "irD2+dRmRahPjwJ0LUdGjHL6/AkrojVSs1IREyo1sVY=", true,
				Arrays.asList(Role.ROLE_ADMIN, Role.ROLE_USER)));
	}

	public Mono<User> findByUsername(String username) {
		log.info("[-- {} --] findByUsername: {}", this.getClass().getSimpleName(), username);
		if (data.containsKey(username)) {
			return Mono.just(data.get(username));
		} else {
			return Mono.empty();
		}
	}

}