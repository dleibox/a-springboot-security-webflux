package a.springboot.security.service;

import a.springboot.security.model.User;
import reactor.core.publisher.Mono;

public interface UserService {

	Mono<User> findByUsername(String username);

}