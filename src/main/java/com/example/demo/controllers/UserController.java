package com.example.demo.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.models.User;
import com.example.demo.services.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1/users")
@Slf4j
public class UserController {
    private final UserService userService;


    // FYI: Response body and response entity are actually not needed, as Rest Controller annotation is used.
    // Endpoint to get all current users. Can use this to test whether issued JWT token is valid or not.
    @GetMapping
    public @ResponseBody ResponseEntity<List<User>> getUsers() {
        return new ResponseEntity<List<User>>(userService.getUsers(), HttpStatus.OK);
    }

    // Endpoint finds user by username.
    @GetMapping("/{username}")
    public @ResponseBody ResponseEntity<User> getUserByUsername(@PathVariable String username) {
        return new ResponseEntity<User>(userService.getUser(username), HttpStatus.OK);
    }

    // Saves new user to DB.
    @PostMapping
    public @ResponseBody ResponseEntity<User> createUser(@RequestBody User newUser) {
        return new ResponseEntity<User>(userService.saveUser(newUser), HttpStatus.CREATED);
    }

    // Refreshes access token when it expires (after 30 mins).
    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader("Authorization");

        // Checking if there is an authorization header in the request, and that a bearer token is included.
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

            // Below we are decoding and verifying the passed in JWT in 'Authorization' header, and issuing a new one.
            try {
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);

                // Subject is information about user encoded in the JWT.
                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);

                // New access token is issued.
                String accessToken = JWT.create()
                        .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(request.getRequestURL().toString())
                        .sign(algorithm);

                // Including new access token and old refresh token in the response back to frontend.
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", accessToken);
                tokens.put("refresh_token", refresh_token);
                response.setContentType("application/json");

                /*
                 * This implementation uses a rather 'outdated' manner of returning JSON. Could simply just send back an
                 * object if you would like. The RestController will serialize whatever object you use to JSON instead
                 * of manually serializing a map. If you want to use headers with responses then you can use ResponseEntity.
                 */
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);

                // Error handling if no JWT token is given or 'Authorization' header does not exist.
            } catch (Exception exception) {
                log.debug("Error logging in" + exception.getMessage());
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());
                Map<String, String> error_message = new HashMap<>();
                error_message.put("error", exception.getMessage());
                new ObjectMapper().writeValue(response.getOutputStream(), error_message);
            }
        } else {
            throw new RuntimeException("Refresh token is missing.");
        }

    }

}
