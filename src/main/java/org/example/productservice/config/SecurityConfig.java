package org.example.productservice.config;

import org.example.productservice.security.JwtAuthenticationFilter;
import org.example.productservice.security.JwtUtil;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.http.HttpStatus;

import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtUtil jwtUtil
    ) throws Exception {

        http
                // Stateless JWT: tắt CSRF cho API
                .csrf(csrf -> csrf.disable())

                // Không lưu trạng thái đăng nhập
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())

                // Chưa đăng nhập: 401
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(
                                new HttpStatusEntryPoint(
                                        HttpStatus.UNAUTHORIZED
                                )
                        )
                )

                // Bắt buộc có JWT cho API Product
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/products",
                                "/api/products/**"
                        ).authenticated()

                        .anyRequest().denyAll()
                )

                // Đăng ký JWT Filter trước UsernamePasswordAuthenticationFilter
                .addFilterBefore(
                        new JwtAuthenticationFilter(jwtUtil),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}
