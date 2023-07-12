package io.fusionauth.quickstart.springapi;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final String ROLES_CLAIM = "roles";

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractRoles(jwt);
        return new UsernamePasswordAuthenticationToken(jwt, jwt.getTokenValue(), authorities);
    }

    private Collection<GrantedAuthority> extractRoles(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();
        if (claims.containsKey(ROLES_CLAIM)) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) claims.get(ROLES_CLAIM);
            return roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
        return List.of();
    }
}
