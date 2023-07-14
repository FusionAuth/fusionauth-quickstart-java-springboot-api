package io.fusionauth.quickstart.springapi;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
public class SecurityConfiguration {

    private final OAuth2ResourceServerProperties properties;

    public SecurityConfiguration(OAuth2ResourceServerProperties properties) {
        this.properties = properties;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        List<String> audiences = properties.getJwt().getAudiences();
        CustomJwtAuthenticationConverter converter = new CustomJwtAuthenticationConverter(audiences);

        return http.authorizeHttpRequests(authz -> authz
                        .requestMatchers("make-change")
                            .hasAnyAuthority("customer", "teller")
                        .requestMatchers("panic")
                            .hasAuthority("teller"))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(converter)))
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withIssuerLocation(properties.getJwt().getIssuerUri()).build();
    }
}
