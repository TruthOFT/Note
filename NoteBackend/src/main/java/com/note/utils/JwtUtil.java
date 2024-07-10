package com.note.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
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

import java.sql.Struct;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

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
        Algorithm algorithm = Algorithm.HMAC256(key);
        Date time = expireTime();
        return JWT.create()
                .withClaim("id", userId)
                .withClaim("username", username)
                .withClaim("auth", details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(time)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public UserDetails toUser(DecodedJWT jwt) {
        return User
                .withUsername(jwt.getClaim("username").asString())
                .password("123456")
                .authorities(jwt.getClaim("auth").asArray(String.class))
                .build();
    }

    public Date expireTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire);
        return calendar.getTime();
    }

    public DecodedJWT parseJwt(String token) {
        String tokenStart = "Bearer ";
        if (token == null || token.isEmpty() || !token.startsWith(tokenStart)) {
            System.out.println("Token is Null");
            return null;
        }
        Algorithm algorithm = Algorithm.HMAC256(key);
        String parsedToken = token.substring(tokenStart.length());
        return JWT.require(algorithm).build().verify(parsedToken);
    }
}
