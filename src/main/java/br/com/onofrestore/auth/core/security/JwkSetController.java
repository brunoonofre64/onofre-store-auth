package br.com.onofrestore.auth.core.security;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class JwkSetController {

    final JWKSet jwkSet;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> keys() {
        return this.jwkSet.toJSONObject();
    }
}
