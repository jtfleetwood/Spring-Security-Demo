package com.example.demo.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@Slf4j
// Filter that checks for valid bearer token (encoded JWT) included in Authorization header for all responses (except /login and token/refresh).
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Checks if request is either attempting to login or refresh a token. Would not need to check for valid bearer token in that case.
        if(request.getServletPath().equals("/login") || request.getServletPath().equals("/api/v1/users/token/refresh/**")) {
            filterChain.doFilter(request, response);
        }

        // Checking for valid bearer token below.
        else {
            String authorizationHeader = request.getHeader("Authorization");

            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

                try {
                    String token = authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = verifier.verify(token);
                    String username = decodedJWT.getSubject();

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<SimpleGrantedAuthority>());
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    // Sending this request and response to the next filter in the filter chain.
                    filterChain.doFilter(request, response);
                }

                // If error with included bearer token, then sending forbidden response to access specific resource.
                catch(Exception exception) {
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                }


            }

            else {
                filterChain.doFilter(request, response);
            }
        }
    }
}
