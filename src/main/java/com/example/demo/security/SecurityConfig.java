package com.example.demo.security;

import com.example.demo.filters.CustomAuthenticationFilter;
import com.example.demo.filters.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
// Configures spring security's needed beans, and configuration.
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // Below used for password encryption.
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // Configures password encoding..
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
        super.configure(auth);
    }


    // Very important below... CORS configuration allows our frontend application to communicate with this application.
    // Please look into CORS, and preflight requests/responses. Essentially, asserts which web origins can communicate with applications.
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "content-type", "x-auth-token"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Protects against CSRF attacks. Not MVP at the moment to protect against these. Try enabling, could present no errors when in use.
        http.csrf().disable();

        // Setting CORS configuration to above.
        http.cors().configurationSource(corsConfigurationSource());
        // Setting application to be stateless.
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        // Allows all requests to be able to reach refresh token endpoint.
        http.authorizeRequests().antMatchers("/api/v1/users/token/refresh/**").permitAll();
        // Allows all requests to be able to reach login endpoint.
        http.authorizeRequests().antMatchers("/login").permitAll();
        // All other requests need a valid bearer token in the 'Authorization' header.
        http.authorizeRequests().anyRequest().authenticated();
        // Adds filter to authenticate user upon reaching the /login endpoint.
        http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
        // Filter to check for valid bearer tokens in incoming requests.
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

    }

    // Bean used in AuthenticationFilter.
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
