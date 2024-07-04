package com.chuca.oauth.auth.service.implement;

import com.chuca.oauth.auth.entity.User;
import com.chuca.oauth.auth.repository.UserRepository;
import com.chuca.oauth.auth.security.OAuth2UserInfo;
import com.chuca.oauth.auth.security.OAuth2UserInfoFactory;
import com.chuca.oauth.auth.security.UserDetailsImpl;
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
    public OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2User.getAttributes());

        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new RuntimeException("Email not found from OAuth2 provider");
        }

        User user = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        if (user != null) {
            if (!user.getSocialProvider().equals("KAKAO")) {
                throw new RuntimeException("Email already signed up.");
            }
            user = updateUser(user, oAuth2UserInfo);
        } else {
            user = registerUser(oAuth2UserInfo);
        }

        return (OAuth2User) UserDetailsImpl.create(user, oAuth2UserInfo.getAttributes());
    }

    private User registerUser(OAuth2UserInfo oAuth2UserInfo) {
        User user = User.builder()
                .userId(oAuth2UserInfo.getName())
                .email(oAuth2UserInfo.getEmail())
                .socialProvider("KAKAO")
                .role("ROLE_USER")
                .build();

        return userRepository.save(user);
    }

    private User updateUser(User user, OAuth2UserInfo oAuth2UserInfo) {
        user.update(oAuth2UserInfo.getName());
        return userRepository.save(user);
    }
}