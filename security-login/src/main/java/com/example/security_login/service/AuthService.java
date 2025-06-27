package com.example.security_login.service;

import com.example.security_login.dto.LoginRequest;
import com.example.security_login.dto.LoginResponse;
import com.example.security_login.dto.RegisterRequest;
import com.example.security_login.dto.UserResponse;
import com.example.security_login.entity.AuthProvider;
import com.example.security_login.entity.User;
import com.example.security_login.exception.CustomException;
import com.example.security_login.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    /**
     * 🔹 일반 로그인
     * - 이메일/비밀번호 검증
     * - JWT 토큰 생성
     * - 로그인 이력 기록
     */
    @Transactional
    public LoginResponse login(LoginRequest loginRequest) {
        log.info("로그인 시도: {}", loginRequest.getEmail());

        try {
            // 1. 사용자 인증
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            // 2. 사용자 정보 조회
            User user = userService.findByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다."));

            // 3. OAuth2 사용자 로그인 시도 차단
            if (!AuthProvider.LOCAL.equals(user.getProvider())) {
                log.warn("OAuth2 사용자의 일반 로그인 시도: {} (제공자: {})",
                        user.getEmail(), user.getProvider());
                throw new CustomException("소셜 로그인으로 가입한 계정입니다. " +
                        user.getProvider().getDisplayName() + " 로그인을 이용해주세요.");
            }

            // 4. JWT 토큰 생성
            String accessToken = jwtTokenProvider.generateAccessToken(authentication);
            String refreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail());

            // 5. Refresh Token 저장
            userService.saveRefreshToken(user.getEmail(), refreshToken);

            log.info("로그인 성공: {} (ID: {})", user.getEmail(), user.getId());

            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(3600L) // 1시간
                    .user(UserResponse.from(user))
                    .build();

        } catch (BadCredentialsException e) {
            log.warn("잘못된 로그인 정보: {}", loginRequest.getEmail());
            throw new CustomException("이메일 또는 비밀번호가 올바르지 않습니다.");
        } catch (DisabledException e) {
            log.warn("비활성화된 계정 로그인 시도: {}", loginRequest.getEmail());
            throw new CustomException("비활성화된 계정입니다. 관리자에게 문의하세요.");
        } catch (AuthenticationException e) {
            log.error("인증 오류: {} - {}", loginRequest.getEmail(), e.getMessage());
            throw new CustomException("로그인 중 오류가 발생했습니다.");
        }
    }

    /**
     * 🔹 회원가입
     * - 입력값 검증
     * - 사용자 생성
     * - 자동 로그인 처리
     */
    @Transactional
    public LoginResponse register(RegisterRequest registerRequest) {
        log.info("회원가입 시도: {}", registerRequest.getEmail());

        // 1. 입력값 검증
        validateRegisterRequest(registerRequest);

        // 2. 사용자 생성
        UserResponse userResponse = userService.registerUser(registerRequest);

        // 3. 자동 로그인 처리
        LoginRequest loginRequest = LoginRequest.builder()
                .email(registerRequest.getEmail())
                .password(registerRequest.getPassword())
                .build();

        LoginResponse loginResponse = login(loginRequest);

        log.info("회원가입 및 자동 로그인 완료: {} (ID: {})",
                userResponse.getEmail(), userResponse.getId());

        return loginResponse;
    }

    /**
     * 🔹 토큰 갱신
     * - Refresh Token 검증
     * - 새로운 Access Token 발급
     */
    @Transactional
    public LoginResponse refreshToken(String refreshToken) {
        log.debug("토큰 갱신 시도");

        // 1. Refresh Token 유효성 검증
        if (!jwtTokenProvider.validateToken(refreshToken) ||
                !jwtTokenProvider.isRefreshToken(refreshToken)) {
            log.warn("유효하지 않은 Refresh Token");
            throw new CustomException("유효하지 않은 Refresh Token입니다.");
        }

        // 2. 사용자 정보 추출
        String email = jwtTokenProvider.getUsernameFromToken(refreshToken);
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new CustomException("사용자를 찾을 수 없습니다."));

        // 3. 저장된 Refresh Token과 비교
        Optional<String> storedRefreshToken = userService.getRefreshToken(email);
        if (storedRefreshToken.isEmpty() || !storedRefreshToken.get().equals(refreshToken)) {
            log.warn("저장된 Refresh Token과 일치하지 않음: {}", email);
            throw new CustomException("유효하지 않은 Refresh Token입니다.");
        }

        // 4. 새로운 토큰 발급
        String newAccessToken = jwtTokenProvider.generateAccessToken(email);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(email);

        // 5. 새로운 Refresh Token 저장
        userService.saveRefreshToken(email, newRefreshToken);

        log.info("토큰 갱신 완료: {}", email);

        return LoginResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(3600L)
                .user(UserResponse.from(user))
                .build();
    }

    /**
     * 🔹 로그아웃
     * - Refresh Token 삭제
     * - 로그아웃 이력 기록
     */
    @Transactional
    public void logout(String email) {
        log.info("로그아웃 요청: {}", email);

        // Refresh Token 삭제
        userService.deleteRefreshToken(email);

        log.info("로그아웃 완료: {}", email);
    }

    /**
     * 🔹 전체 로그아웃 (모든 기기에서)
     * - 모든 Refresh Token 무효화
     */
    @Transactional
    public void logoutFromAllDevices(String email) {
        log.info("전체 로그아웃 요청: {}", email);

        // 모든 Refresh Token 삭제
        userService.deleteRefreshToken(email);

        // TODO: 실제 운영에서는 Redis 등에서 사용자의 모든 토큰을 무효화

        log.info("전체 로그아웃 완료: {}", email);
    }

    /**
     * 🔹 이메일 중복 확인
     */
    @Transactional(readOnly = true)
    public boolean isEmailAvailable(String email) {
        boolean available = !userService.findByEmail(email).isPresent();
        log.debug("이메일 중복 확인: {} - {}", email, available ? "사용 가능" : "사용 불가");
        return available;
    }

    /**
     * 🔹 비밀번호 재설정 요청
     */
    @Transactional
    public void requestPasswordReset(String email) {
        log.info("비밀번호 재설정 요청: {}", email);

        User user = userService.findByEmail(email)
                .orElseThrow(() -> new CustomException("등록되지 않은 이메일입니다."));

        // OAuth2 사용자 확인
        if (!AuthProvider.LOCAL.equals(user.getProvider())) {
            throw new CustomException("소셜 로그인 사용자는 비밀번호 재설정을 할 수 없습니다.");
        }

        // TODO: 실제 운영에서는 이메일 발송 로직 구현
        // - 임시 토큰 생성
        // - 이메일로 재설정 링크 발송
        // - 토큰의 유효시간 설정 (예: 30분)

        log.info("비밀번호 재설정 이메일 발송 완료: {}", email);
    }

    /**
     * 🔹 회원가입 요청 검증
     */
    private void validateRegisterRequest(RegisterRequest request) {
        // 이메일 형식 검증
        if (!isValidEmail(request.getEmail())) {
            throw new CustomException("올바른 이메일 형식이 아닙니다.");
        }

        // 비밀번호 강도 검증
        if (!isValidPassword(request.getPassword())) {
            throw new CustomException("비밀번호는 8자 이상이며, 영문, 숫자, 특수문자를 포함해야 합니다.");
        }

        // 이름 검증
        if (request.getName() == null || request.getName().trim().length() < 2) {
            throw new CustomException("이름은 2자 이상이어야 합니다.");
        }
    }

    /**
     * 🔹 이메일 형식 검증
     */
    private boolean isValidEmail(String email) {
        return email != null &&
                email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    /**
     * 🔹 비밀번호 강도 검증
     */
    private boolean isValidPassword(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }

        // 영문, 숫자, 특수문자 포함 검증
        boolean hasLetter = password.matches(".*[A-Za-z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSpecialChar = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*");

        return hasLetter && hasDigit && hasSpecialChar;
    }
}