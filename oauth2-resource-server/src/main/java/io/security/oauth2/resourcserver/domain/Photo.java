package io.security.oauth2.resourcserver.domain;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Photo {

    private String id;
    private String userId;
    private String title;
    private String description;

}
