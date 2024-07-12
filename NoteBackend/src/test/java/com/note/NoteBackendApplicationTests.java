package com.note;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.note.constant.Constant;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.text.SimpleDateFormat;
import java.util.*;

@SpringBootTest
class NoteBackendApplicationTests {

    private static final int EXPIRE_HOUR = 3;
    private static final Algorithm algorithm = Algorithm.HMAC256("key");

    @Resource
    StringRedisTemplate template;

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

    DecodedJWT decodedJWT(String token) {
        try {
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token);
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    @Test
    void contextLoads() {
        // token Test
//        String token = createJwt();
//        System.out.println(token);
////
//        DecodedJWT decodedJWT = decodedJWT(token);
//        System.out.println(decodedJWT.getClaims().get("id").asInt());
//        Date expiresAt = decodedJWT.getExpiresAt();
//        Date now = new Date();
//        template.opsForValue().set(Constant.JWT_BLACK_LIST_START + UUID.randomUUID(), "This is test value");
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode("123456"));

    }

}
