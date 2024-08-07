package com.note.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.note.constant.Constant;
import com.note.entity.dto.Account;
import com.note.service.UserService;
import jakarta.annotation.Resource;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Component
public class JwtUtil {

    @Value("${spring.security.jwt.key}")
    String key;

    @Value("${spring.security.jwt.expire}")
    Integer expire;

    @Resource
    StringRedisTemplate stringRedisTemplate;

    @Resource
    UserService userService;

    private final String tokenStart = "Bearer ";

    public boolean delToken(String token) {
        DecodedJWT decodedJWT = parseJwt(token);
        if (decodedJWT == null) return false;
        Date expireDate = decodedJWT.getExpiresAt();
        Date now = new Date();
        long expireTime = Math.max(expireDate.getTime() - now.getTime(), 0);
        String uuid = decodedJWT.getId();
        stringRedisTemplate.opsForValue().set(Constant.JWT_BLACK_LIST_START + uuid, "black token " + uuid, expireTime, TimeUnit.MILLISECONDS);
        return true;
    }

    public String createJwt(UserDetails details, int userId, String username) {
        Date time = expireTime();
        Algorithm algorithm = Algorithm.HMAC256(key);
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id", userId)
                .withClaim("username", username)
                .withClaim("auth", details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(time)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public DecodedJWT parseJwt(String token) {
        if (token == null || !token.startsWith(tokenStart)) {
            return null;
        }
        String willBeParsedToken = token.substring(tokenStart.length());
        try {
            Algorithm algorithm = Algorithm.HMAC256(key);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(willBeParsedToken);
            if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(Constant.JWT_BLACK_LIST_START + decodedJWT.getId()))) {
                return null;
            }
            return decodedJWT;
        } catch (JWTVerificationException e) {
            e.printStackTrace();
            return null;
        }

    }

    public UserDetails jwtToUser(DecodedJWT jwt) {
        Account account = userService.findUserByUsernameOrEmail(jwt.getClaim("username").asString());
        return User
                .withUsername(account.getUsername())
                .password(account.getPassword())
                .authorities(jwt.getClaim("auth").asArray(String.class))
                .build();
    }

    public Date expireTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire);
        return calendar.getTime();
    }
}
