package io.security.oauth2.inflearnspringsecurityoauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;

@Controller
public class LoginController {

    @Autowired
    private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    @Autowired
    private OAuth2AuthorizedClientRepository authorizedClientRepository;

    private final Duration clockSkew = Duration.ofSeconds(60 * 60);
    private final Clock clock = Clock.systemUTC();

    @GetMapping("oauth2Login")
    public String oauth2Login(HttpServletRequest request, HttpServletResponse response, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthorizeRequest auth2AuthorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();
        OAuth2AuthorizedClient authorize = oAuth2AuthorizedClientManager.authorize(auth2AuthorizeRequest);

        OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> authorizedClientRepository
                .saveAuthorizedClient(
                        authorizedClient,
                        principal,
                        (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                        (HttpServletResponse) attributes.get(HttpServletResponse.class.getName())
                );

        oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);

        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(auth2AuthorizeRequest);

        // 권한 부여 타입을 변경하지 않고 실행
//        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
//            oAuth2AuthorizedClientManager.authorize(auth2AuthorizeRequest);
//        }

        // 권한 부여 타입을 변경하고 실행
        if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
            ClientRegistration clientRegistration = ClientRegistration
                    .withClientRegistration(authorizedClient.getClientRegistration())
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

            OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(clientRegistration, authorizedClient.getPrincipalName(), authorizedClient.getAccessToken(), authorizedClient.getRefreshToken());

            OAuth2AuthorizeRequest authorizeRequest2 = OAuth2AuthorizeRequest
                    .withAuthorizedClient(oAuth2AuthorizedClient)
                    .principal(authentication)
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build();

            oAuth2AuthorizedClientManager.authorize(authorizeRequest2);

        }

        model.addAttribute("accessToken", authorize.getAccessToken().getTokenValue());
        model.addAttribute("refreshToken", authorize.getRefreshToken().getTokenValue());
        return "home";
    }

    @GetMapping("logout")
    public String logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        return "redirect:/";
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

}