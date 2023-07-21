package io.security.oauth2.resourcserver.filter.authorization;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

public abstract class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JWSVerifier jwsVerifier;

    public JwtAuthorizationFilter(JWSVerifier jwsVerifier) {
        this.jwsVerifier = jwsVerifier;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (tokenResolve(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = getToken(request);

        SignedJWT signedJWT;

        try {
            signedJWT = SignedJWT.parse(token);
            boolean verify = signedJWT.verify(jwsVerifier);

            if (verify) {
                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
                String username = (String) jwtClaimsSet.getClaim("username");
                List<String> authority = (List<String>) jwtClaimsSet.getClaim("authority");

                if (StringUtils.hasText(username)) {
                    UserDetails user = User.builder()
                            .username(username)
                            .password(UUID.randomUUID().toString())
                            .authorities(authority.get(0))
                            .build();

                    Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request, response);
    }

    protected String getToken(HttpServletRequest request) {
        return request.getHeader("Authorization").replace("Bearer ", "");
    }

    protected boolean tokenResolve(HttpServletRequest request) throws IOException, ServletException {
        String header = request.getHeader("Authorization");
        return header == null || !header.startsWith("Bearer ");
    }

}
