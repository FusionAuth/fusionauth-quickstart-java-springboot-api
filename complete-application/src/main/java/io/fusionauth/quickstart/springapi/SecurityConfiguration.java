package io.fusionauth.quickstart.springapi;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Lyle Schemmerling
 */
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(authz -> authz
                        .requestMatchers("make-change")
                            .hasAnyAuthority("customer", "teller")
                        .requestMatchers("panic")
                            .hasAuthority("teller"))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(new CustomJwtAuthenticationConverter())
                                       .jwkSetUri("http://localhost:9011/.well-known/jwks.json")
                        ))
                .build();
    }
}
