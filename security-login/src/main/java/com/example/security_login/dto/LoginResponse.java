package com.example.security_login.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
// 로그인 응답 dto
public class LoginResponse {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private Long expiresIn;  // 토큰 만료시간 (초)
    private UserResponse user;

    @Builder.Default
    private String message = "로그인 성공";
}