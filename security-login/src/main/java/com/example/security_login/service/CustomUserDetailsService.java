package com.example.security_login.service;

import com.example.security_login.entity.User;
import com.example.security_login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Spring Security에서 사용하는 사용자 정보 로드
     * @param username 사용자명 (이메일)
     * @return UserDetails 구현체 (User 엔티티)
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("사용자 정보 로드 시도: {}", username);

        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> {
                    log.warn("사용자를 찾을 수 없습니다: {}", username);
                    return new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username);
                });

        // 계정 상태 검증
        validateUserAccount(user);

        log.debug("사용자 정보 로드 완료: {} (권한: {})", username, user.getRole());
        return user;
    }

    /**
     * 사용자 ID로 사용자 정보 로드
     * @param userId 사용자 ID
     * @return UserDetails 구현체 (User 엔티티)
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(Long userId) throws UsernameNotFoundException {
        log.debug("사용자 정보 로드 시도 (ID): {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("사용자를 찾을 수 없습니다 (ID): {}", userId);
                    return new UsernameNotFoundException("사용자를 찾을 수 없습니다 (ID): " + userId);
                });

        validateUserAccount(user);

        log.debug("사용자 정보 로드 완료 (ID): {} - {}", userId, user.getEmail());
        return user;
    }

    /**
     * 사용자 계정 상태 검증
     * @param user 검증할 사용자
     */
    private void validateUserAccount(User user) {
        if (!user.isEnabled()) {
            log.warn("비활성화된 계정: {}", user.getEmail());
            throw new UsernameNotFoundException("비활성화된 계정입니다: " + user.getEmail());
        }

        if (!user.isAccountNonLocked()) {
            log.warn("잠긴 계정: {}", user.getEmail());
            throw new UsernameNotFoundException("잠긴 계정입니다: " + user.getEmail());
        }

        if (!user.isAccountNonExpired()) {
            log.warn("만료된 계정: {}", user.getEmail());
            throw new UsernameNotFoundException("만료된 계정입니다: " + user.getEmail());
        }

        if (!user.isCredentialsNonExpired()) {
            log.warn("인증 정보가 만료된 계정: {}", user.getEmail());
            throw new UsernameNotFoundException("인증 정보가 만료된 계정입니다: " + user.getEmail());
        }
    }

    /**
     * 사용자 존재 여부 확인
     * @param email 이메일
     * @return 존재 여부
     */
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    /**
     * 활성화된 사용자인지 확인
     * @param email 이메일
     * @return 활성화 여부
     */
    @Transactional(readOnly = true)
    public boolean isActiveUser(String email) {
        return userRepository.findByEmail(email)
                .map(User::isEnabled)
                .orElse(false);
    }
}