package io.security.oauth2.resourcserver.dto;

import lombok.Data;
import org.springframework.security.core.Authentication;

@Data
public class OpaqueDto {

    private boolean active;
    private Authentication authentication;
    private Object principal;

}
