//package com.chuca.oauth.auth.controller;
//
//import com.chuca.oauth.auth.security.JwtTokenProvider;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//@Slf4j
//@RestController
//@RequestMapping("/api/users")
//@RequiredArgsConstructor
//public class UserController {
//
//    private final JwtTokenProvider jwtTokenProvider;
//    private final UserService userService;
//
//
//    @PostMapping("/login/kakao")
//    public ResultTemplate login(@RequestBody RequestLoginDto requestLoginDto) {
//
//        LoginDto user = userService.findKakaoUserByAuthorizedCode(requestLoginDto.getCode(), RedirectUrlProperties.KAKAO_REDIRECT_URL);
//        String accessToken = jwtTokenProvider.createAccessToken(user.getUserId(), String.valueOf(user.getUserId()), user.getSocialType());
//        String refreshToken = jwtTokenProvider.createRefreshToken(user.getUserId());
//
//        // 리프레시토큰 레디스에 저장한다
//        jwtTokenProvider.storeRefreshToken(user.getUserId(), refreshToken);
//
//        ResponseLoginDto responseLoginDto = ResponseLoginDto.builder()
//                .userId(user.getUserId())
//                .name(user.getNickname())
//                .AccessToken(accessToken)
//                .RefreshToken(refreshToken)
//                .build();
//
//        return ResultTemplate.builder()
//                .status(HttpStatus.OK.value())
//                .data(responseLoginDto)
//                .build();
//    }
//}
