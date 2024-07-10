package com.note;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.Set;

@SpringBootTest
class NoteBackendApplicationTests {

    private static final int EXPIRE_HOUR = 3;
    private static final Algorithm algorithm = Algorithm.HMAC256("key");
    String createJwt() {
        return JWT.create()
                .withClaim("id", 123)
                .withClaim("username", "Truth")
                .withClaim("auth", "admin")
                .withExpiresAt(expireDate())
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    Date expireDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, EXPIRE_HOUR);
        return calendar.getTime();
    }

    Map<String, Claim> decodedJWT(String token) {
        try {
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token).getClaims();
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    @Test
    void contextLoads() {
        String token = createJwt();
        System.out.println(token);

        Map<String, Claim> stringClaimMap = decodedJWT(token);
        System.out.println(stringClaimMap.get("id").asInt());
    }

}
