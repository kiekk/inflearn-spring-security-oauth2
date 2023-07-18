package io.security.oauth2.inflearnspringsecurityoauth2.util;

import io.security.oauth2.inflearnspringsecurityoauth2.entity.Attributes;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.PrincipalUser;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.Map;

public class OAuth2Utils {

    public static Attributes getMainAttributes(OAuth2User oAuth2User) {

        return Attributes.builder()
                .mainAttributes(oAuth2User.getAttributes())
                .build();
    }

    public static Attributes getSubAttributes(OAuth2User oAuth2User, String subAttributesKey) {
        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get(subAttributesKey);
        return Attributes.builder()
                .subAttributes(subAttributes)
                .build();
    }

    public static Attributes getOtherAttributes(OAuth2User oAuth2User, String subAttributesKey, String otherAttributesKey) {
        Map<String, Object> subAttributes = (Map<String, Object>) oAuth2User.getAttributes().get(subAttributesKey);
        Map<String, Object> otherAttributes = (Map<String, Object>) subAttributes.get(otherAttributesKey);

        return Attributes.builder()
                .subAttributes(subAttributes)
                .otherAttributes(otherAttributes)
                .build();
    }

    public static String oAuth2UserName(OAuth2AuthenticationToken auth2Authentication, PrincipalUser principalUser) {
        String userName;
        String registrationId = auth2Authentication.getAuthorizedClientRegistrationId();
        OAuth2User oAuth2User = principalUser.providerUser().getOAuth2User();

        // Google, Facebook, Apple...
        Attributes attributes = OAuth2Utils.getMainAttributes(oAuth2User);

        switch (registrationId) {
            case "naver" -> {
                attributes = OAuth2Utils.getSubAttributes(oAuth2User, "response");
                userName = (String) attributes.getSubAttributes().get("name");
            }
            case "keycloak" -> {
                attributes = OAuth2Utils.getMainAttributes(oAuth2User);
                userName = (String) attributes.getMainAttributes().get("preferred_username");
            }
            case "kakao" -> {
                // OpenID Connect
                if (oAuth2User instanceof OidcUser) {
                    attributes = OAuth2Utils.getMainAttributes(oAuth2User);
                    userName = (String) attributes.getMainAttributes().get("nickname");
                } else {
                    attributes = OAuth2Utils.getOtherAttributes(principalUser, "profile", null);
                    userName = (String) attributes.getSubAttributes().get("nickname");
                }
            }
            default -> {
                userName = (String) attributes.getMainAttributes().get("name");
            }
        }
        return userName;
    }
}