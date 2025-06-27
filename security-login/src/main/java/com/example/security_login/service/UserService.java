package com.example.security_login.service;

import com.example.security_login.dto.RegisterRequest;
import com.example.security_login.dto.UserResponse;
import com.example.security_login.entity.AuthProvider;
import com.example.security_login.entity.Role;
import com.example.security_login.entity.User;
import com.example.security_login.exception.CustomException;
import com.example.security_login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Refresh Token 저장소 (실제 운영에서는 Redis 등 사용 권장)
    private final Map<String, String> refreshTokenStore = new ConcurrentHashMap<>();

    /**
     * 일반 회원가입
     * - 이메일 중복 검사
     * - 비밀번호 암호화
     * - 사용자 정보 저장
     */
    @Transactional
    public UserResponse registerUser(RegisterRequest request) {
        log.info("일반 회원가입 시도: {}", request.getEmail());

        // 이메일 중복 검사
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("이미 존재하는 이메일: {}", request.getEmail());
            throw new CustomException("이미 사용 중인 이메일입니다.");
        }

        // 전화번호 중복 검사
        if (request.getPhoneNumber() != null &&
                userRepository.findByPhoneNumber(request.getPhoneNumber()).isPresent()) {
            log.warn("이미 존재하는 전화번호: {}", request.getPhoneNumber());
            throw new CustomException("이미 사용 중인 전화번호입니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        // 사용자 생성
        User user = User.createLocalUser(
                request.getEmail(),
                encodedPassword,
                request.getName(),
                request.getPhoneNumber()
        );

        User savedUser = userRepository.save(user);
        log.info("일반 회원가입 완료: {} (ID: {})", savedUser.getEmail(), savedUser.getId());

        return UserResponse.from(savedUser);
    }

    /**
     * OAuth2 사용자 처리
     * - 기존 사용자면 정보 업데이트
     * - 신규 사용자면 자동 가입
     */
    @Transactional
    public User processOAuth2User(OAuth2User oAuth2User, String registrationId) {
        log.info("OAuth2 사용자 처리 시도: provider={}", registrationId);

        // OAuth2 사용자 정보 추출
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

        if (userInfo.getEmail() == null || userInfo.getEmail().isEmpty()) {
            log.error("OAuth2 제공자에서 이메일을 가져올 수 없습니다: {}", registrationId);
            throw new CustomException("OAuth2 제공자에서 이메일을 가져올 수 없습니다.");
        }

        AuthProvider provider = AuthProvider.fromString(registrationId.toUpperCase());

        // 기존 사용자 검색
        Optional<User> existingUser = userRepository.findByProviderAndProviderId(
                provider, userInfo.getId()
        );

        if (existingUser.isPresent()) {
            // 기존 사용자 정보 업데이트
            return updateExistingOAuth2User(existingUser.get(), userInfo);
        } else {
            // 같은 이메일로 다른 제공자 계정이 있는지 확인
            Optional<User> userByEmail = userRepository.findByEmail(userInfo.getEmail());
            if (userByEmail.isPresent()) {
                log.warn("이미 존재하는 이메일로 다른 OAuth2 로그인 시도: {}", userInfo.getEmail());
                throw new CustomException("해당 이메일은 이미 다른 계정에서 사용 중입니다.");
            }

            // 신규 사용자 생성
            return createNewOAuth2User(userInfo, provider);
        }
    }

    /**
     * 기존 OAuth2 사용자 정보 업데이트
     */
    private User updateExistingOAuth2User(User existingUser, OAuth2UserInfo userInfo) {
        log.info("기존 OAuth2 사용자 정보 업데이트: {}", existingUser.getEmail());

        // 필요한 경우 사용자 정보 업데이트
        boolean isUpdated = false;

        if (!existingUser.getName().equals(userInfo.getName())) {
            existingUser.setName(userInfo.getName());
            isUpdated = true;
        }

        if (isUpdated) {
            existingUser = userRepository.save(existingUser);
            log.info("OAuth2 사용자 정보 업데이트 완료: {}", existingUser.getEmail());
        }

        return existingUser;
    }

    /**
     * 신규 OAuth2 사용자 생성
     */
    private User createNewOAuth2User(OAuth2UserInfo userInfo, AuthProvider provider) {
        log.info("신규 OAuth2 사용자 생성: email={}, provider={}", userInfo.getEmail(), provider);

        User user = User.createOAuth2User(
                userInfo.getEmail(),
                userInfo.getName(),
                provider,
                userInfo.getId()
        );

        User savedUser = userRepository.save(user);
        log.info("OAuth2 회원가입 완료: {} (ID: {})", savedUser.getEmail(), savedUser.getId());

        return savedUser;
    }

    /**
     * 사용자 조회 (이메일)
     */
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * 사용자 조회 (ID)
     */
    @Transactional(readOnly = true)
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    /**
     * 모든 사용자 조회 (관리자용)
     */
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserResponse::from)
                .toList();
    }

    /**
     * 사용자 검색 (이름)
     */
    @Transactional(readOnly = true)
    public List<UserResponse> searchUsersByName(String name) {
        return userRepository.findByNameContainingIgnoreCase(name)
                .stream()
                .map(UserResponse::from)
                .toList();
    }

    /**
     * 사용자 비활성화
     */
    @Transactional
    public void deactivateUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다."));

        user.setEnabled(false);
        userRepository.save(user);

        log.info("사용자 비활성화 완료: {}", user.getEmail());
    }

    /**
     * 사용자 활성화
     */
    @Transactional
    public void activateUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다."));

        user.setEnabled(true);
        userRepository.save(user);

        log.info("사용자 활성화 완료: {}", user.getEmail());
    }

    /**
     * 비밀번호 변경
     */
    @Transactional
    public void changePassword(String email, String oldPassword, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다."));

        // OAuth2 사용자는 비밀번호 변경 불가
        if (!AuthProvider.LOCAL.equals(user.getProvider())) {
            throw new CustomException("소셜 로그인 사용자는 비밀번호를 변경할 수 없습니다.");
        }

        // 기존 비밀번호 확인
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new CustomException("기존 비밀번호가 올바르지 않습니다.");
        }

        // 새 비밀번호 암호화 및 저장
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        log.info("비밀번호 변경 완료: {}", user.getEmail());
    }

    /**
     * Refresh Token 저장
     */
    public void saveRefreshToken(String email, String refreshToken) {
        refreshTokenStore.put(email, refreshToken);
        log.debug("Refresh Token 저장 완료: {}", email);
    }

    /**
     * Refresh Token 조회
     */
    public Optional<String> getRefreshToken(String email) {
        return Optional.ofNullable(refreshTokenStore.get(email));
    }

    /**
     * Refresh Token 삭제
     */
    public void deleteRefreshToken(String email) {
        refreshTokenStore.remove(email);
        log.debug("Refresh Token 삭제 완료: {}", email);
    }

    /**
     * 사용자 통계 조회 (관리자용)
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getUserStatistics() {
        long totalUsers = userRepository.count();
        long localUsers = userRepository.countByProvider(AuthProvider.LOCAL);
        long googleUsers = userRepository.countByProvider(AuthProvider.GOOGLE);
        long kakaoUsers = userRepository.countByProvider(AuthProvider.KAKAO);
        long naverUsers = userRepository.countByProvider(AuthProvider.NAVER);

        return Map.of(
                "total", totalUsers,
                "local", localUsers,
                "google", googleUsers,
                "kakao", kakaoUsers,
                "naver", naverUsers
        );
    }
}