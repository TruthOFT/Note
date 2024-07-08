package com.note.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
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

    public Date expireTime()  {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire);
        return calendar.getTime();
    }
}
