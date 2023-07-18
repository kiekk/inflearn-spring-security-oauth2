package io.security.oauth2.inflearnspringsecurityoauth2.converters;

import io.security.oauth2.inflearnspringsecurityoauth2.entity.ProviderUser;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.List;

@Component
public class DelegatingProviderUserConverter<T, R> implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {

    private final List<ProviderUserConverter<ProviderUserRequest, ProviderUser>> converters;

    public DelegatingProviderUserConverter() {
        this.converters = List.of(
                new UserDetailsProviderUserConverter(),
                new OAuth2GoogleProviderUserConverter(),
                new OAuth2NaverProviderUserConverter(),
                new OAuth2KakaoProviderUserConverter(),
                new OAuth2KakaoOidcProviderUserConverter(),
                new OAuth2FacebookProviderUserConverter(),
                new OAuth2KeycloakProviderUserConverter(),
                new OAuth2MicrosoftProviderUserConverter()
        );
    }

    @Override
    public ProviderUser converter(ProviderUserRequest providerUserRequest) {
        Assert.notNull(providerUserRequest, "providerUserRequest cannot be null");

        for (ProviderUserConverter<ProviderUserRequest, ProviderUser> converter : converters) {
            ProviderUser providerUser = converter.converter(providerUserRequest);
            if (providerUser != null) {
                return providerUser;
            }
        }
        return null;
    }
}
