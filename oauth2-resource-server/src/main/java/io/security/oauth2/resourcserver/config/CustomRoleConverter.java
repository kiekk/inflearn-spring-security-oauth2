package io.security.oauth2.resourcserver.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

public class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        String scopes = jwt.getClaim("scope");
        Map<String, Object> realm_access = jwt.getClaim("realm_access");

        if (!StringUtils.hasText(scopes) || realm_access.isEmpty()) {
            return Collections.emptyList();
        }

        Collection<GrantedAuthority> authorities1 = Arrays.stream(scopes.split(" "))
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        Collection<GrantedAuthority> authorities2 = ((List<String>) realm_access.get("roles")).stream()
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        authorities1.addAll(authorities2);
        return authorities1;
    }
}
