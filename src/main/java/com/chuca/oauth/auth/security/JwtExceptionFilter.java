package com.chuca.oauth.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.HashMap;
import java.util.Map;

@Component
public class JwtExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, JwtException, java.io.IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException | java.io.IOException ex) {
            setErrorResponse(request, response, (JwtException) ex);
        }
    }

    private void setErrorResponse(HttpServletRequest req, HttpServletResponse res, JwtException ex) throws IOException, java.io.IOException {

        res.setContentType(MediaType.APPLICATION_JSON_VALUE);

        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        // ex.getMessage() 에는 jwtException을 발생시키면서 입력한 메세지가 들어있다.
        body.put("message", ex.getMessage());
        body.put("path", req.getServletPath());
        final ObjectMapper mapper = new ObjectMapper();
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        mapper.writeValue(res.getOutputStream(), body);
    }
}
