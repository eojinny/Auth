package com.chuca.oauth.auth.security;

import com.chuca.oauth.auth.common.ResponseCode;
import com.chuca.oauth.auth.common.ResponseMessage;
import com.chuca.oauth.auth.entity.User;
import com.chuca.oauth.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j(topic = "JwtAuthenticationFilter_로그인,JWT 생성")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter( JwtUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        setFilterProcessesUrl("/api/user/login");
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            SignInRequestDto requestDto = new ObjectMapper().readValue(request.getInputStream(), SignInRequestDto.class);

            // 여기서 비밀번호 인증까지 진행함.
            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            requestDto.getId(),
                            requestDto.getPassword()
                    )
            );
        } catch (IOException e) {
            log.error(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }

    // 로그인 성공 시
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        String user_id = ((UserDetailsImpl) authResult.getPrincipal()).getUserEntity().getUserId();

        String accessToken = jwtUtil.createAccessToken(user_id);
        String refreshToken = jwtUtil.createRefreshToken(user_id);


        User userEntity = ((UserDetailsImpl)authResult.getPrincipal()).getUserEntity();

        //리프레쉬 토큰 초기화
        userEntity.refreshTokenReset(refreshToken);
        userRepository.save(userEntity);

        // 응답 헤더에 토큰 추가
        response.addHeader(JwtUtil.AUTHORIZATION_HEADER, accessToken);

        // JSON 응답 작성
        writeJsonResponse(response);

        log.info("User = {}, message = {}", user_id, "로그인 성공.");
    }

    private void writeJsonResponse(HttpServletResponse response) throws IOException {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("code", ResponseCode.SUCCESS);
        responseData.put("message", ResponseMessage.SUCCESS);
        responseData.put("data", "로그인 성공");

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(responseData));
        response.getWriter().flush();
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        try {
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("code", ResponseCode.SIGN_IN_FAIL);
            responseData.put("message", ResponseMessage.SIGN_IN_FAIL);
            responseData.put("data", "로그인 실패");

            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(new ObjectMapper().writeValueAsString(responseData));
        }
        catch (IOException e) {
            log.error("응답 데이터를 작성하는 중 오류 발생", e);
        }
    }

}
