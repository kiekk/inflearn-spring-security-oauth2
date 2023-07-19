package io.security.oauth2.resourcserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import io.security.oauth2.resourcserver.filter.authentication.JwtAuthenticationFilter;
import io.security.oauth2.resourcserver.filter.authorization.JwtAuthorizationMacFilter;
import io.security.oauth2.resourcserver.filter.authorization.JwtAuthorizationRsaFilter;
import io.security.oauth2.resourcserver.signature.MacSecuritySigner;
import io.security.oauth2.resourcserver.signature.RsaSecuritySigner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
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
                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()))
                .addFilterBefore(jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(jwtAuthorizationRsaFilter(null), UsernamePasswordAuthenticationFilter.class) // RSA
//                .addFilterBefore(jwtAuthorizationMacFilter(null), UsernamePasswordAuthenticationFilter.class) // MAC
                .build();
    }

    // RSA
    @Bean
    JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
    }

    // RSA
    @Bean
    JwtAuthenticationFilter jwtAuthenticationFilter(RsaSecuritySigner rsaSecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaSecuritySigner, rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
        return jwtAuthenticationFilter;
    }

    // MAC
//    @Bean
//    JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
//        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
//    }

    // MAC
//    @Bean
//    JwtAuthenticationFilter jwtAuthenticationFilter(MacSecuritySigner macSecuritySigner, OctetSequenceKey octetSequenceKey) throws Exception {
//        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(macSecuritySigner, octetSequenceKey);
//        jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
//        return jwtAuthenticationFilter;
//    }

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
