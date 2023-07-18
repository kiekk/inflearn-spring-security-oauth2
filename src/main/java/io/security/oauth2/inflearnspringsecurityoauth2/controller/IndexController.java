package io.security.oauth2.inflearnspringsecurityoauth2.controller;

import io.security.oauth2.inflearnspringsecurityoauth2.entity.PrincipalUser;
import io.security.oauth2.inflearnspringsecurityoauth2.util.OAuth2Utils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping({"", "/"})
    public String index(Model model, Authentication authentication, @AuthenticationPrincipal PrincipalUser principalUser) {

        if (authentication != null) {

            String userName;

            if (authentication instanceof OAuth2AuthenticationToken) {
                userName = OAuth2Utils.oAuth2UserName((OAuth2AuthenticationToken) authentication, principalUser);
            } else {
                userName = principalUser.providerUser().getUsername();
            }

            model.addAttribute("user", userName);
            model.addAttribute("provider", principalUser.providerUser().getProvider());
        }

        return "index";
    }

    @GetMapping("login")
    public String login() {
        return "login";
    }
}

