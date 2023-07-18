package io.security.oauth2.inflearnspringsecurityoauth2.converters;

import io.security.oauth2.inflearnspringsecurityoauth2.entity.ProviderUser;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.form.FormUser;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.users.User;

public class UserDetailsProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {
    @Override
    public ProviderUser converter(ProviderUserRequest providerUserRequest) {
        User user = providerUserRequest.user();

        if (user == null) {
            return null;
        }

        return FormUser.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .email(user.getEmail())
                .authorities(user.getAuthorities())
                .provider("none")
                .build();
    }
}
