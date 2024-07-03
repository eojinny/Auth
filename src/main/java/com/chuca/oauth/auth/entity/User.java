package com.chuca.oauth.auth.entity;

import com.chuca.oauth.auth.dto.SignUpRequestDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Entity(name="user")
@Table(name="user")
public class User{

    @Id
    @Column(name = "user_id", nullable = false, unique = true)
    private Long userId;

    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "social_provider")
    private String socialProvider;

    private String role;

    @Column(name = "refresh_token")
    private String refreshToken;

    public User(SignUpRequestDto signUpRequestDto) {
        this.userId = signUpRequestDto.getId();
        this.password = signUpRequestDto.getPassword();
        this.email = signUpRequestDto.getEmail();
        this.socialProvider = "app"; // 일반 가입자로 초기화
        this.role = "ROLE_USER"; // 권한 일단 모두 이용자로 초기화
    }

    @Transactional
    public void refreshTokenReset(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
