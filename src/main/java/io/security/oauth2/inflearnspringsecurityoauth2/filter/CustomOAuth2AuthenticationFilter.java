package io.security.oauth2.inflearnspringsecurityoauth2.filter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class CustomOAuth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final String DEFAULT_FILTER_PROCESSING_URL = "/oauth2Login/**";

    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final OAuth2AuthorizationSuccessHandler authorizationSuccessHandler;

    private final Duration clockSkew = Duration.ofSeconds(60 * 60);
    private final Clock clock = Clock.systemUTC();

    public CustomOAuth2AuthenticationFilter(DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager, OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
        super(DEFAULT_FILTER_PROCESSING_URL);
        this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
        this.authorizedClientRepository = oAuth2AuthorizedClientRepository;

        this.authorizationSuccessHandler = (authorizedClient, authentication, attributes) ->
                authorizedClientRepository
                        .saveAuthorizedClient(authorizedClient, authentication,
                                (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                                (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
        this.oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(authorizationSuccessHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();

        if (principal == null) {
            principal = new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        }

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(principal)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);

        if (oAuth2AuthorizedClient != null && hasTokenExpired(oAuth2AuthorizedClient.getAccessToken())
                && oAuth2AuthorizedClient.getRefreshToken() != null) {
            oAuth2AuthorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
        }

        if (oAuth2AuthorizedClient != null) {
            ClientRegistration clientRegistration = oAuth2AuthorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = oAuth2AuthorizedClient.getAccessToken();

            OAuth2UserService oAuth2UserService = new DefaultOAuth2UserService();
            OAuth2User oauth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(
                    oAuth2AuthorizedClient.getClientRegistration(), accessToken));

            SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
            Collection<? extends GrantedAuthority> authorities = simpleAuthorityMapper.mapAuthorities(oauth2User.getAuthorities());
            OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(oauth2User, authorities, clientRegistration.getRegistrationId());

            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

            this.authorizationSuccessHandler.onAuthorizationSuccess(oAuth2AuthorizedClient, oAuth2AuthenticationToken,
                    createAttributes(request, response));

            return oAuth2AuthenticationToken;
        }

        return null;
    }

    private static Map<String, Object> createAttributes(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(HttpServletRequest.class.getName(), servletRequest);
        attributes.put(HttpServletResponse.class.getName(), servletResponse);
        return attributes;
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }
}
