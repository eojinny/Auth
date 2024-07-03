package com.chuca.oauth.auth.security;

import com.chuca.oauth.auth.common.ResponseCode;
import com.chuca.oauth.auth.common.ResponseMessage;
import com.chuca.oauth.auth.entity.User;
import com.chuca.oauth.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.info("시큐리티 인증 필터 진입함 ::: doFilterInternal 메서드");

        // 헤더에서 JWT 받는다
        String accessToken = jwtTokenProvider.extractAccessToken(request).orElse(null);

        log.info("추출한 Access Token:::: " + accessToken);

        // 유효 토큰 검사
        if(accessToken != null && jwtTokenProvider.validateToken(accessToken)) {
            // 유효한 토큰일 때 토큰을 통해 유저 정보를 받아온다
            Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
            // SecurityContext 요기다가 Authentication 객체를 저장한다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("유효 토큰 검사 완료. 해당 유저 인가 처리 완료");
        }

        // null 일때 처리: 더 들어오지 않고 내보낸다 - 일단 보류요 ..

        filterChain.doFilter(request, response);

    }
}