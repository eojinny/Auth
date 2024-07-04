package com.chuca.oauth.auth.security;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(Map<String, Object> attributes) {
        return new KakaoOAuth2User(attributes);
    }
}