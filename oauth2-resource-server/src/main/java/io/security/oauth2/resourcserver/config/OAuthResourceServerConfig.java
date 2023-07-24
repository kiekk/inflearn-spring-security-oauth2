package io.security.oauth2.resourcserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class OAuthResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/photos/1")
                .authorizeHttpRequests(authz ->
                        authz
                                .requestMatchers("/photos/1").hasAuthority("SCOPE_photo")
                                .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/photos/2", "/photos/3")
                .authorizeHttpRequests(authz ->
                        authz
                                .requestMatchers("/photos/2").permitAll()
                                .requestMatchers("/photos/3").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()))
                .build();
    }

}
