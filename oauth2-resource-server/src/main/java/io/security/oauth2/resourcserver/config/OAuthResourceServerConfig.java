package io.security.oauth2.resourcserver.config;

import com.nimbusds.jose.jwk.RSAKey;
import io.security.oauth2.resourcserver.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2.resourcserver.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import io.security.oauth2.resourcserver.signature.RsaPublicKeySecuritySigner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class OAuthResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz ->
                        authz
                                .requestMatchers("/").permitAll()
                                .anyRequest().authenticated()
                )
                .userDetailsService(userDetailsService())
                .addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthorizationRsaPublicKeyFilter(null), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicKeyFilter(JwtDecoder jwtDecoder) {
        return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
    }

    @Bean
    JwtAuthenticationFilter jwtAuthenticationFilter(RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaPublicKeySecuritySigner, rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    @Bean
    UserDetailsService userDetailsService() {
        String password = passwordEncoder().encode("1234");
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("user")
                        .password(password)
                        .roles("USER")
                        .build()
        );
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

}
