package io.security.oauth2.resourcserver;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static io.security.oauth2.resourcserver.jwk.JWKTest.jwk;

@SpringBootApplication
public class Oauth2ResourceServerApplication {

    public static void main(String[] args) throws Exception {
        jwk();
//        SpringApplication.run(Oauth2ResourceServerApplication.class, args);
    }

}
