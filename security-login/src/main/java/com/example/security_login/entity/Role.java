package com.example.security_login.entity;

/**
 * 사용자 권한 열거형
 */
public enum Role {
    USER("일반 사용자"),
    ADMIN("관리자");

    private final String description;

    Role(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Spring Security에서 사용할 권한 문자열 반환
     */
    public String getAuthority() {
        return "ROLE_" + this.name();
    }
}