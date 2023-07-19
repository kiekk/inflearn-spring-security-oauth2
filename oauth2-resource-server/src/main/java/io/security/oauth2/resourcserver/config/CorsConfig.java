package io.security.oauth2.resourcserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    // https://docs.spring.io/spring-security/reference/reactive/integrations/cors.html
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true); // 인증 처리 허용
        configuration.setAllowedOrigins(List.of("*")); // 도메인 허용
        configuration.setAllowedHeaders(List.of("*")); // 헤더 허용
        configuration.setAllowedMethods(List.of("*")); // Http Method 허용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }

}
