package com.example.security_login.entity;

/**
 * OAuth2 인증 제공자 열거형
 */
public enum AuthProvider {
    LOCAL("일반 로그인"),
    GOOGLE("구글"),
    KAKAO("카카오"),
    NAVER("네이버");

    private final String displayName;

    AuthProvider(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * 문자열로부터 AuthProvider 찾기
     */
    public static AuthProvider fromString(String provider) {
        for (AuthProvider authProvider : AuthProvider.values()) {
            if (authProvider.name().equalsIgnoreCase(provider)) {
                return authProvider;
            }
        }
        throw new IllegalArgumentException("Unknown provider: " + provider);
    }
}