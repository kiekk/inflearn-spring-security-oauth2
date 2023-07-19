package io.security.oauth2.resourcserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.security.oauth2.resourcserver.signature.MacSecuritySigner;
import io.security.oauth2.resourcserver.signature.RsaSecuritySigner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SignatureConfig {

    @Bean
    MacSecuritySigner macSecuritySigner() {
        return new MacSecuritySigner();
    }

    @Bean
    OctetSequenceKey octetSequenceKey() throws JOSEException {
        return new OctetSequenceKeyGenerator(256)
                .keyID("macKey")
                .algorithm(JWSAlgorithm.HS256)
                .generate();
    }

    @Bean
    RsaSecuritySigner rsaSecuritySigner() {
        return new RsaSecuritySigner();
    }

    @Bean
    RSAKey rsaKey() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyID("rsaKey")
                .algorithm(JWSAlgorithm.RS256)
                .generate();
    }

}
