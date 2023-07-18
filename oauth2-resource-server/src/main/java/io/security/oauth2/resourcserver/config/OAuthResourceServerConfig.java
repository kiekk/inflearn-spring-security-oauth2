package io.security.oauth2.resourcserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class OAuthResourceServerConfig {

    @Autowired
    private OAuth2ResourceServerProperties properties;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
//    @Primary
    JwtDecoder jwtDecoder1() {
        return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
    }

    @Bean
//    @Primary
    JwtDecoder jwtDecoder2() {
        return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
    }

    @Bean
    @Primary
    JwtDecoder jwtDecoder3() {
        return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS512)
                .build();
    }

}
