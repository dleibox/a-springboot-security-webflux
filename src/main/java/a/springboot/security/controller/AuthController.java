package a.springboot.security.controller;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import a.springboot.security.model.AuthRequest;
import a.springboot.security.model.AuthResponse;
import a.springboot.security.service.UserService;
import a.springboot.security.utils.JwtUtil;
import reactor.core.publisher.Mono;

@RestController
public class AuthController {

	private static final Logger log = LoggerFactory.getLogger(AuthController.class);

	@Autowired
	@Qualifier("JwtRsa")
	private JwtUtil jwtUtil;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private UserService userService;

//	@PreAuthorize("permitAll()") // won't work if .anyExchange().authenticated()
//	@PreAuthorize("isAuthenticated()")
	@RequestMapping(value = "/", method = RequestMethod.GET)
	public Mono<ResponseEntity<?>> welcome(Principal principal) {
		log.info("[-- {} --] principal: {}", this.getClass().getSimpleName(), principal);
		Map<String, String> obj = new HashMap<String, String>() {{
			put("hi", "welcome");
			put("login", "/login");
			put("user", "/resource/user");
			put("admin", "/resource/admin");
			put("user-or-admin", "/resource/user-or-admin");
		}};
		return Mono.just(ResponseEntity.ok(obj));
	}

	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public Mono<ResponseEntity<?>> login(@RequestBody AuthRequest ar) {
		log.info("[-- {} --] req: {}", this.getClass().getSimpleName(), ar);
		return userService.findByUsername(ar.getUsername()).map((userDetails) -> {
			log.info("[-- {} --] passwordEncoder: {}", this.getClass().getSimpleName(),
					passwordEncoder.encode(ar.getPassword()));
			if (passwordEncoder.matches(ar.getPassword(), userDetails.getPassword())) {
				return ResponseEntity.ok(new AuthResponse(jwtUtil.generateToken(userDetails)));
			} else {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
			}
		}).defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
	}
}
