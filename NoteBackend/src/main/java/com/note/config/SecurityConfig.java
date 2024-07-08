package com.note.config;

import com.auth0.jwt.JWT;
import com.note.entity.RestBean;
import com.note.utils.JwtUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;

@Configuration
public class SecurityConfig {

    @Resource
    JwtUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(login -> login.loginProcessingUrl("/api/auth/login")
                        .successHandler(this::onAuthenticationSuccess))
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }

    private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        User user = (User) authentication.getPrincipal();
        String token = jwtUtil.createJwt(user, 1, user.getUsername());
        response.getWriter().write(RestBean.success(token, "登录成功").asJsonString());
    }
}
