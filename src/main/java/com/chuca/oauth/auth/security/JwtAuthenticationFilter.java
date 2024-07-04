package com.chuca.oauth.auth.security;

import com.chuca.oauth.auth.common.ResponseCode;
import com.chuca.oauth.auth.common.ResponseMessage;
import com.chuca.oauth.auth.entity.User;
import com.chuca.oauth.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        log.info("시큐리티 인증 필터 진입함 ::: doFilterInternal 메서드");

        // 헤더에서 JWT 받는다
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) servletRequest);

        log.info("추출한 Access Token:::: " + token);

        // 유효 토큰 검사
        if(token != null && jwtTokenProvider.validateToken(token)) {
            // 유효한 토큰일 때 토큰을 통해 유저 정보를 받아온다
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            // SecurityContext 요기다가 Authentication 객체를 저장한다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("유효 토큰 검사 완료. 해당 유저 인가 처리 완료");
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}