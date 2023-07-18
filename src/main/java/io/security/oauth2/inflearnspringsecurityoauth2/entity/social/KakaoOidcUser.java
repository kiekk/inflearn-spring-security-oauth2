package io.security.oauth2.inflearnspringsecurityoauth2.entity.social;

import io.security.oauth2.inflearnspringsecurityoauth2.entity.Attributes;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.OAuth2ProviderUser;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class KakaoOidcUser extends OAuth2ProviderUser {

    public KakaoOidcUser(Attributes attributes, OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(attributes.getMainAttributes(), oAuth2User, clientRegistration);
    }

    @Override
    public String getId() {
        return (String) getAttributes().get("email");
    }

    @Override
    public String getUsername() {
        return (String) getAttributes().get("nickname");
    }

    @Override
    public String getPicture() {
        return (String) getAttributes().get("profile_image_url");
    }
}
