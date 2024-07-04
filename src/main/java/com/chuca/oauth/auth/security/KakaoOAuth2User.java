package com.chuca.oauth.auth.security;

import lombok.Getter;
import lombok.AllArgsConstructor;

import java.util.Map;

@Getter
@AllArgsConstructor
public class KakaoOAuth2User {

    private Map<String, Object> attributes;


    public String getEmail() {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        return kakaoAccount.get("email").toString();
    }

    public String getName() {
        Map<String, Object> properties = (Map<String, Object>) attributes.get("profile");
        return properties.get("nickname").toString();
    }
}