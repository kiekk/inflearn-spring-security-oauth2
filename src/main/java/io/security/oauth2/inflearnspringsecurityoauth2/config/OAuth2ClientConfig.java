package io.security.oauth2.inflearnspringsecurityoauth2.config;

import io.security.oauth2.inflearnspringsecurityoauth2.CustomAuthorityMapper;
import io.security.oauth2.inflearnspringsecurityoauth2.service.CustomOAuth2UserService;
import io.security.oauth2.inflearnspringsecurityoauth2.service.CustomOidcUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http,
                                                  CustomOAuth2UserService customOAuth2UserService,
                                                  CustomOidcUserService customOidcUserService) throws Exception {
        return http
                .authorizeHttpRequests((authz) -> {
                    authz
                            // static resources setting
                            .requestMatchers("/static/**").permitAll()
                            .requestMatchers("/api/user/**").hasAnyRole("SCOPE_profile", "SCOPE_email")
                            .requestMatchers("/api/oidc/**").hasAnyRole("SCOPE_openid")
                            .requestMatchers("/").permitAll()
                            .anyRequest().authenticated();
                })
                .formLogin(formLogin -> {
                    formLogin
                            .loginPage("/login")
                            .loginProcessingUrl("/loginProc")
                            .defaultSuccessUrl("/")
                            .permitAll();
                })
                .oauth2Login(oauth2Login -> {
                    oauth2Login.userInfoEndpoint(userInfoEndpointConfig -> {
                        userInfoEndpointConfig
                                .userService(customOAuth2UserService)
                                .oidcUserService(customOidcUserService);
                    });
                })
                .logout(logout -> {
                    logout
                            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                            .logoutSuccessUrl("/login");
                })
                .exceptionHandling(exceptionHandling -> {
                    exceptionHandling.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
                })
                .build();
    }

    @Bean
    public GrantedAuthoritiesMapper customGrantedAuthoritiesMapper() {
        return new CustomAuthorityMapper();
    }

}
