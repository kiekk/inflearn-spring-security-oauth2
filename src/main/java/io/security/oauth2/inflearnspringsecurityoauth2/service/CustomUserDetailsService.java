package io.security.oauth2.inflearnspringsecurityoauth2.service;

import io.security.oauth2.inflearnspringsecurityoauth2.converters.ProviderUserRequest;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.PrincipalUser;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.ProviderUser;
import io.security.oauth2.inflearnspringsecurityoauth2.entity.users.User;
import io.security.oauth2.inflearnspringsecurityoauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService extends AbstractOAuth2UserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if(user == null) {
            user = User.builder()
                    .id("1")
                    .username("user1")
                    .password("{noop}1234")
                    .authorities(AuthorityUtils.createAuthorityList("ROLE_USER"))
                    .email("user@a.com")
                    .build();
        }
        ProviderUserRequest providerUserRequest = new ProviderUserRequest(user);
        ProviderUser providerUser = providerUser(providerUserRequest);

        return new PrincipalUser(providerUser);
    }
}
