package io.security.oauth2.resourcserver.controller;

import io.security.oauth2.resourcserver.domain.Photo;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

    @GetMapping("/photos/1")
    public Photo photo1() {
        return Photo.builder()
                .id("1")
                .title("Photo 1 title")
                .description("Photo is nice")
                .userId("user1")
                .build();
    }

    @GetMapping("/photos/2")
    public Photo photo2() {
        return Photo.builder()
                .id("2")
                .title("Photo 2 title")
                .description("Photo is beautiful")
                .userId("user2")
                .build();
    }

    @GetMapping("/photos/3")
    @PreAuthorize("hasAnyAuthority('SCOPE_photo')")
    public Photo photo3(Authentication authentication) {
        return Photo.builder()
                .id("3")
                .title("Photo 3 title")
                .description("Photo is beautiful")
                .userId("user3")
                .build();
    }


}
