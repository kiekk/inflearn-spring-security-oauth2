package io.security.oauth2.resourcserver;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import static io.security.oauth2.resourcserver.jca.MessageDigestTest.messageDigest;
import static io.security.oauth2.resourcserver.jca.SignatureTest.signature;

@SpringBootApplication
public class Oauth2ResourceServerApplication {

    public static void main(String[] args) throws Exception {
//        messageDigest("Spring Security");
        signature("Spring Security");
//        SpringApplication.run(Oauth2ResourceServerApplication.class, args);
    }

}
