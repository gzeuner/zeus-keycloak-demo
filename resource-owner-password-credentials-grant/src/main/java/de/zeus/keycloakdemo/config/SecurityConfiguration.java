package de.zeus.keycloakdemo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Value("${keycloak.logout.url}")
    private String logoutSuccessUrl;

    @Value("${spring.security.oauth2.client.provider.external.issuer-uri}")
    private String issuerUri;

    private static final String JWK_SET_URI = "http://localhost:8080/realms/olymp/protocol/openid-connect/certs";
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/", "/index.html", "/public", "/public.html", "/oauth2/**", "/login/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer()
                .jwt(); // oder .opaqueToken(), abhängig von deinem Token-Typ

        http
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl(logoutSuccessUrl)
                .invalidateHttpSession(true)
                .clearAuthentication(true);

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        String jwkSetUri = issuerUri + "/protocol/openid-connect/certs";
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }
}


