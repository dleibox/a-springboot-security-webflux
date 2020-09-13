package a.springboot.security.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import a.springboot.security.model.Message;
import reactor.core.publisher.Mono;

@RestController
public class ResourceController {
	
	private static final Logger log = LoggerFactory.getLogger(ResourceController.class);
	
	@RequestMapping(value = "/resource/user", method = RequestMethod.GET)
	@PreAuthorize("hasRole('USER')")
	public Mono<ResponseEntity<?>> user() {
		log.info("[-- {} --] resource: {}", this.getClass().getSimpleName(), "user");
		return Mono.just(ResponseEntity.ok(new Message("Content for user")));
	}
	
	@RequestMapping(value = "/resource/admin", method = RequestMethod.GET)
	@PreAuthorize("hasRole('ADMIN')")
	public Mono<ResponseEntity<?>> admin() {
		log.info("[-- {} --] resource: {}", this.getClass().getSimpleName(), "admin");
		return Mono.just(ResponseEntity.ok(new Message("Content for admin")));
	}
	
	@RequestMapping(value = "/resource/user-or-admin", method = RequestMethod.GET)
	@PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
	public Mono<ResponseEntity<?>> userOrAdmin() {
		log.info("[-- {} --] resource: {}", this.getClass().getSimpleName(), "user or admin");
		return Mono.just(ResponseEntity.ok(new Message("Content for user or admin")));
	}
}