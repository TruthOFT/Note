package com.note.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.note.constant.Constant;
import jakarta.annotation.Resource;
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

@Component
public class JwtUtil {


    @Value("${spring.security.jwt.key}")
    String key;

    @Value("${spring.security.jwt.expire}")
    Integer expire;

    @Resource
    StringRedisTemplate stringRedisTemplate;

    /**
     * @param token 用户登录Token
     * @return 是否修改token时间成功
     */
    public boolean changeTokenTime(String token) {
        String tokenStart = "Bearer ";
        if (token == null || token.isEmpty() || !token.startsWith(tokenStart)) {
            return false;
        }
        String parsedToken = token.substring(tokenStart.length());
        try {
            Algorithm algorithm = Algorithm.HMAC256(key);
            DecodedJWT decodedJWT = JWT.require(algorithm).build().verify(parsedToken);
            String uuid = decodedJWT.getId();
            if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(Constant.JWT_BLACK_LIST_START + uuid))) {
                return false;
            }
            Date expiresAt = decodedJWT.getExpiresAt();
            Date now = new Date();
            long expire = (expiresAt.getTime() - now.getTime()) < 0 ? 0 : expiresAt.getTime() - now.getTime();
            stringRedisTemplate.opsForValue().set(Constant.JWT_BLACK_LIST_START + uuid, "token", expire, TimeUnit.MILLISECONDS);
            return true;
        } catch (JWTVerificationException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    /**
     * @param details  登录的用户信息 由 Security onAuthenticationSuccess之后传入
     * @param userId   UserId
     * @param username UserName
     * @return Jwt字符串
     */
    public String createJwt(UserDetails details, int userId, String username) {
        Algorithm algorithm = Algorithm.HMAC256(key);
        Date time = expireTime();
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id", userId)
                .withClaim("username", username)
                .withClaim("auth", details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(time)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    /**
     * @param jwt DecodedJWT认证对象
     * @return 返回认证成功后的用户认证信息
     */
    public UserDetails toUser(DecodedJWT jwt) {
        return User
                .withUsername(jwt.getClaim("username").asString())
                .password("123456")
                .authorities(jwt.getClaim("auth").asArray(String.class))
                .build();
    }

    /**
     * @return 设置Token过期时间
     */
    public Date expireTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire);
        return calendar.getTime();
    }

    /**
     * @param token 需要被解析的Jwt字符串
     * @return 认证完成后的DecodedJWT对象, 可以进一步处理
     */
    public DecodedJWT parseJwt(String token) {
        String tokenStart = "Bearer ";
        if (token == null || token.isEmpty() || !token.startsWith(tokenStart)) {
            return null;
        }
        String parsedToken = token.substring(tokenStart.length());
        try {
            Algorithm algorithm = Algorithm.HMAC256(key);
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decodedJWT = verifier.verify(token);
            String uuid = decodedJWT.getId();
            if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(Constant.JWT_BLACK_LIST_START + uuid))) {
                System.out.println("Blanked Token");
                return null;
            }
            return verifier.verify(parsedToken);
        } catch (JWTVerificationException e) {
            return null;
        }

    }
}
