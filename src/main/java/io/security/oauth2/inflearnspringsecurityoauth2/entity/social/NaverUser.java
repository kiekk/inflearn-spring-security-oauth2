package io.security.oauth2.inflearnspringsecurityoauth2.entity.social;

import io.security.oauth2.inflearnspringsecurityoauth2.entity.Attributes;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.OAuth2ProviderUser;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class NaverUser extends OAuth2ProviderUser {

    public NaverUser(Attributes attributes, OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(attributes.getSubAttributes(), oAuth2User, clientRegistration);
    }

    @Override
    public String getId() {
        return (String) getAttributes().get("id");
    }

    @Override
    public String getUsername() {
        return (String) getAttributes().get("email");
    }

    @Override
    public String getPicture() {
        return (String) getAttributes().get("profile_image");
    }

}
