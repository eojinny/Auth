package com.chuca.oauth.auth.service.implement;

import com.chuca.oauth.auth.entity.User;
import com.chuca.oauth.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.AuthProvider;

@Service
@RequiredArgsConstructor
public class OAuth2UserServiceImplement extends DefaultOAuth2UserService {

    private  final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return super.loadUser(userRequest);
    }
//    protected OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
//        //OAuth2 로그인 플랫폼 구분
//        AuthProvider authProvider = AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId().toUpperCase());
//        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(authProvider, oAuth2User.getAttributes());
//
//        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
//            throw new RuntimeException("Email not found from OAuth2 provider");
//        }
//        User user = userRepository.findByEmail(oAuth2UserInfo.getEmail()).orElse(null);
//        //이미 가입된 경우
//        if (user != null) {
//            if (!user.getAuthProvider().equals(authProvider)) {
//                throw new RuntimeException("Email already signed up.");
//            }
//            user = updateUser(user, oAuth2UserInfo);
//        }
//        //가입되지 않은 경우
//        else {
//            user = registerUser(authProvider, oAuth2UserInfo);
//        }
//        return UserPrincipal.create(user, oAuth2UserInfo.getAttributes());
//    }


}
