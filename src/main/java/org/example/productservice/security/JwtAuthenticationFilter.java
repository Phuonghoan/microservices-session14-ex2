package org.example.productservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Đọc Authorization Header
        String authorization =
                request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorization != null
                && authorization.startsWith("Bearer ")) {

            String token = authorization.substring(7).trim();

            try {

                // 2. Xác minh chữ ký và hạn sử dụng JWT
                Claims claims = jwtUtil.extractClaims(token);

                // 3. Lấy username và role từ Claims
                String username = claims.getSubject();
                String role = claims.get("role", String.class);

                if (username == null || username.isBlank()
                        || role == null || role.isBlank()) {

                    throw new JwtException(
                            "JWT thiếu username hoặc role"
                    );
                }

                // 4. Chuyển role thành Authority
                // Identity-Service đang cấp USER hoặc ADMIN
                String authority = role.startsWith("ROLE_")
                        ? role
                        : "ROLE_" + role;

                SimpleGrantedAuthority grantedAuthority =
                        new SimpleGrantedAuthority(authority);

                // 5. Tạo Authentication từ JWT đã xác minh
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                List.of(grantedAuthority)
                        );

                // 6. Lưu vào SecurityContext
                SecurityContextHolder.getContext()
                        .setAuthentication(authentication);

                System.out.println(
                        "JWT hợp lệ | User: " + username
                                + " | Role: " + role
                );

            } catch (JwtException | IllegalArgumentException e) {

                SecurityContextHolder.clearContext();

                response.sendError(
                        HttpServletResponse.SC_UNAUTHORIZED,
                        "Invalid or expired JWT"
                );

                return;
            }
        }

        // 7. Cho request đi tiếp
        filterChain.doFilter(request, response);
    }
}
