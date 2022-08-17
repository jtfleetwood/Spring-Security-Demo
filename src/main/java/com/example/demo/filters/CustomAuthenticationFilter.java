package com.example.demo.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
// Below is an implementation of a filter. A filter is essentially an object that intercepts HTTP requests and responses. Kind of like NodeJS middleware.
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;


    // Below method executes everytime a POST request is made to the login endpoint to attempt authentication.
    @Override
    public Authentication attemptAuthentication( HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // Weird syntax is due to a user model that we later use from spring security having the same type name (userdetails.user).
        com.example.demo.models.User newUser = new com.example.demo.models.User();

        // Manually parsing body from request. Probably could just use a user object instead of this approach.
        try {
            ObjectMapper mapper = new ObjectMapper();
            String auth = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
            newUser = mapper.readValue(auth, com.example.demo.models.User.class);

            System.out.print("Username: " + newUser.getUsername());
        }

        catch(Exception e) {
            System.out.print(e.getMessage());
        }

        // Authentication object that will be passed to the below method upon successfully authenticating.
        // If any operation in this method fails, user will be returned a 403 (forbidden repsonse).
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(newUser.getUsername(), newUser.getPassword());
        return authenticationManager.authenticate(authenticationToken);
    }


    // Method that returns an issued JWT token to the authenticated user. Response status is 203 (successful).
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        // Logged in user of type userdetails (spring security user object).
        User user = (User)authentication.getPrincipal();

        // Creating JWT to issue..
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        String accessToken = JWT.create()
                .withSubject(user.getUsername())
                // Setting token to last for 10 mins. Value is in ms.
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        // Creating refresh token to be used in case access token expires during session.
        String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        /*
            Again, outdated way of handling JSON response. I believe this approach is used to separate concerns from
            controller -> filters. Technically, this is not a controller and should not be sending responses. So, we
            need this response object. Map object is essentially the same things as our needed JSON response however.
         */
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        tokens.put("user", user.getUsername());
        response.setContentType("application/json");

        // Writing map object to response.
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);

    }
}
