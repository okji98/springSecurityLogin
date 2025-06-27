package com.example.security_login.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    @Column(name = "phone_number")
    private String phoneNumber;

    // OAuth2 관련 필드
    @Enumerated(EnumType.STRING)
    @Column(name = "provider")
    private AuthProvider provider;  // GOOGLE, KAKAO, NAVER, LOCAL

    @Column(name = "provider_id")
    private String providerId;  // OAuth2 제공자의 사용자 ID

    // 권한
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Role role = Role.USER;  // USER, ADMIN

    // 계정 상태
    @Builder.Default
    @Column(name = "account_non_expired")
    private boolean accountNonExpired = true;

    @Builder.Default
    @Column(name = "account_non_locked")
    private boolean accountNonLocked = true;

    @Builder.Default
    @Column(name = "credentials_non_expired")
    private boolean credentialsNonExpired = true;

    @Builder.Default
    private boolean enabled = true;

    // 생성/수정 시간
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // UserDetails 인터페이스 구현
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email;  // 이메일을 username으로 사용
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    // OAuth2 사용자 생성을 위한 정적 메서드
    public static User createOAuth2User(String email, String name, AuthProvider provider, String providerId) {
        return User.builder()
                .email(email)
                .name(name)
                .password("") // OAuth2 사용자는 패스워드 없음
                .provider(provider)
                .providerId(providerId)
                .role(Role.USER)
                .build();
    }

    // 일반 회원가입 사용자 생성을 위한 정적 메서드
    public static User createLocalUser(String email, String password, String name, String phoneNumber) {
        return User.builder()
                .email(email)
                .password(password)
                .name(name)
                .phoneNumber(phoneNumber)
                .provider(AuthProvider.LOCAL)
                .role(Role.USER)
                .build();
    }
}