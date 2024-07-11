package com.note.config;

import com.note.entity.RestBean;
import com.note.entity.vo.response.AuthorizeVO;
import com.note.filter.JwtFilter;
import com.note.utils.JwtUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
public class SecurityConfig {

    @Resource
    JwtUtil jwtUtil;

    @Resource
    JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth.requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(login -> login.loginProcessingUrl("/api/auth/login")
                        .successHandler(this::onAuthenticationSuccess)
                        .failureHandler(this::onAuthenticationFailure))
                .logout(logout -> logout.logoutUrl("/auth/test/logout")
                        .logoutSuccessHandler(this::onLogoutSuccess))
                .exceptionHandling(handler -> handler.authenticationEntryPoint(this::commence))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s ->
                        s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        User user = (User) authentication.getPrincipal();
        String token = jwtUtil.createJwt(user, 1, user.getUsername());
        AuthorizeVO authorizeVO = new AuthorizeVO(user.getUsername(), "", token, jwtUtil.expireTime());
        response.getWriter().write(RestBean.success(authorizeVO, "登录成功").asJsonString());
    }

    private void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.failure(401, exception.getMessage(), "登录失败").asJsonString());
    }

    private void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        System.out.println("认证失败");
        response.getWriter().write(RestBean.failure(401, null, authException.getMessage()).asJsonString());
    }

    private void onLogoutSuccess(HttpServletRequest request,
                                 HttpServletResponse response,
                                 Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        String authorization = request.getHeader("Authorization");
        boolean isChanged = jwtUtil.changeTokenTime(authorization);
        if (isChanged) {
            response.getWriter().write(RestBean.success().asJsonString());
        } else {
            response.getWriter().write(RestBean.failure().asJsonString());
        }
    }
}
