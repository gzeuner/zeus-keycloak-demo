package de.zeus.keycloakdemo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Value("${keycloak.logout.url}")
    private String logoutSuccessUrl;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                // OAuth2 configuration
                .oauth2Client()
                .and()
                .oauth2Login()
                .tokenEndpoint()
                .and()
                .userInfoEndpoint();

        // Session management
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

        // Authorization rules
        http
                .authorizeHttpRequests()
                .requestMatchers(
                        "/",            // Root URL
                        "/index.html",  // Home page
                        "/public",      // Public endpoints
                        "/public.html",
                        "/oauth2/**",   // OAuth2 endpoints
                        "/login/**"     // Login endpoints
                ).permitAll()
                .requestMatchers("/logoutWithoutConfirmation") // Protect logoutWithoutConfirmation
                .authenticated()
                .anyRequest()
                .fullyAuthenticated();

        // Logout configuration
        http
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl(logoutSuccessUrl)
                .invalidateHttpSession(true) // Ensures session invalidation
                .clearAuthentication(true);  // Clears authentication context
        
        return http.build();
    }
}
