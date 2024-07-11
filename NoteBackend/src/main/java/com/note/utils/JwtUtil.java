package com.note.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Component
public class JwtUtil {

    @Value("${spring.security.jwt.key}")
    String key;

    @Value("${spring.security.jwt.expire}")
    Integer expire;

    public String createJwt(UserDetails details, int userId, String username) {
        Date time = expireTime();
        Algorithm algorithm = Algorithm.HMAC256(key);
        return JWT.create()
                .withClaim("id", userId)
                .withClaim("username", username)
                .withClaim("auth", details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(time)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public DecodedJWT parseJwt(String token) {
        String tokenStart = "Bearer ";
        if (token == null || token.isEmpty() || !token.startsWith(tokenStart)) {
            return null;
        }
        String willBeParsedToken = token.substring(tokenStart.length());
        try {
            Algorithm algorithm = Algorithm.HMAC256(key);
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(willBeParsedToken);
        } catch (JWTVerificationException e) {
            e.printStackTrace();
            return null;
        }

    }

    public UserDetails jwtToUser(DecodedJWT jwt) {
        return User
                .withUsername(jwt.getClaim("username").asString())
                .password("123")
                .authorities(jwt.getClaim("auth").asArray(String.class))
                .build();
    }

    public Date expireTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire);
        return calendar.getTime();
    }
}
