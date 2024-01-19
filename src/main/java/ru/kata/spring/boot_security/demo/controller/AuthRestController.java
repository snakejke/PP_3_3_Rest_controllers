package ru.kata.spring.boot_security.demo.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import ru.kata.spring.boot_security.demo.model.User;

@RestController
@RequestMapping("/api/auth")
public class AuthRestController {

    private final DaoAuthenticationProvider daoAuthenticationProvider;

    public AuthRestController(DaoAuthenticationProvider daoAuthenticationProvider) {
        this.daoAuthenticationProvider = daoAuthenticationProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<String> authenticateUser(@Valid @RequestBody User user,
            HttpServletRequest request, HttpServletResponse response) {
        Authentication authenticationToken = new UsernamePasswordAuthenticationToken(
                user.getEmail(), user.getPassword());

        try {
            Authentication authentication = daoAuthenticationProvider.authenticate(
                    authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jsessionId = getJSessionIdFromSecurityContext();
            response.addHeader(HttpHeaders.SET_COOKIE, "JSESSIONID=" + jsessionId);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("Authentication successful! JSESSIONID: " + jsessionId);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Authentication failed!");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser() {
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok().body("You've been signed out!");
    }

    private String getJSessionIdFromSecurityContext() {
        return RequestContextHolder.currentRequestAttributes()
                .getSessionId();
    }
}


