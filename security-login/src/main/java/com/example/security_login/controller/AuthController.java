package com.example.security_login.controller;

import com.example.security_login.dto.*;
import com.example.security_login.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * 일반 로그인 API
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletResponse response) {

        log.info("로그인 API 호출: {}", loginRequest.getEmail());

        try {
            // 로그인 처리
            LoginResponse loginResponse = authService.login(loginRequest);

            // 쿠키에 토큰 저장 (선택사항)
            if (loginRequest.isRememberMe()) {
                addTokenToCookie(response, "access_token",
                        loginResponse.getAccessToken(), 3600); // 1시간
                addTokenToCookie(response, "refresh_token",
                        loginResponse.getRefreshToken(), 1209600); // 14일
            }

            return ResponseEntity.ok(
                    ApiResponse.success("로그인이 성공적으로 완료되었습니다.", loginResponse)
            );

        } catch (Exception e) {
            log.error("로그인 실패: {} - {}", loginRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 회원가입 API
     * POST /api/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<LoginResponse>> register(
            @Valid @RequestBody RegisterRequest registerRequest) {

        log.info("회원가입 API 호출: {}", registerRequest.getEmail());

        try {
            // 회원가입 및 자동 로그인
            LoginResponse loginResponse = authService.register(registerRequest);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("회원가입이 성공적으로 완료되었습니다.", loginResponse));

        } catch (Exception e) {
            log.error("회원가입 실패: {} - {}", registerRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 토큰 갱신 API
     * POST /api/auth/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(
            @RequestBody(required = false) String refreshToken,
            HttpServletRequest request) {

        log.info("토큰 갱신 API 호출");

        try {
            // Refresh Token 추출 (Body → Cookie → Header 순서로)
            String token = extractRefreshToken(refreshToken, request);

            if (token == null || token.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.failure("Refresh Token이 제공되지 않았습니다."));
            }

            // 토큰 갱신
            LoginResponse loginResponse = authService.refreshToken(token);

            return ResponseEntity.ok(
                    ApiResponse.success("토큰이 성공적으로 갱신되었습니다.", loginResponse)
            );

        } catch (Exception e) {
            log.error("토큰 갱신 실패: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 로그아웃 API
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(
            Authentication authentication,
            HttpServletResponse response) {

        if (authentication != null && authentication.isAuthenticated()) {
            String email = authentication.getName();
            log.info("로그아웃 API 호출: {}", email);

            try {
                // 로그아웃 처리
                authService.logout(email);

                // 쿠키에서 토큰 제거
                removeTokenFromCookie(response, "access_token");
                removeTokenFromCookie(response, "refresh_token");

                return ResponseEntity.ok(
                        ApiResponse.success("로그아웃이 성공적으로 완료되었습니다.", "SUCCESS")
                );

            } catch (Exception e) {
                log.error("로그아웃 실패: {} - {}", email, e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponse.failure("로그아웃 처리 중 오류가 발생했습니다."));
            }
        }

        return ResponseEntity.ok(
                ApiResponse.success("로그아웃이 완료되었습니다.", "SUCCESS")
        );
    }

    /**
     * 전체 로그아웃 API (모든 기기에서 로그아웃)
     * POST /api/auth/logout-all
     */
    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<String>> logoutFromAllDevices(
            Authentication authentication,
            HttpServletResponse response) {

        if (authentication != null && authentication.isAuthenticated()) {
            String email = authentication.getName();
            log.info("전체 로그아웃 API 호출: {}", email);

            try {
                // 모든 기기에서 로그아웃
                authService.logoutFromAllDevices(email);

                // 쿠키에서 토큰 제거
                removeTokenFromCookie(response, "access_token");
                removeTokenFromCookie(response, "refresh_token");

                return ResponseEntity.ok(
                        ApiResponse.success("모든 기기에서 로그아웃되었습니다.", "SUCCESS")
                );

            } catch (Exception e) {
                log.error("전체 로그아웃 실패: {} - {}", email, e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponse.failure("로그아웃 처리 중 오류가 발생했습니다."));
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.failure("인증되지 않은 사용자입니다."));
    }

    /**
     * 이메일 중복 확인 API
     * GET /api/auth/check-email?email={email}
     */
    @GetMapping("/check-email")
    public ResponseEntity<ApiResponse<Boolean>> checkEmailAvailability(
            @RequestParam String email) {

        log.debug("이메일 중복 확인 API 호출: {}", email);

        try {
            boolean isAvailable = authService.isEmailAvailable(email);
            String message = isAvailable ? "사용 가능한 이메일입니다." : "이미 사용 중인 이메일입니다.";

            return ResponseEntity.ok(
                    ApiResponse.success(message, isAvailable)
            );

        } catch (Exception e) {
            log.error("이메일 중복 확인 실패: {} - {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("이메일 확인 중 오류가 발생했습니다."));
        }
    }

    /**
     * 비밀번호 재설정 요청 API
     * POST /api/auth/forgot-password
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(
            @RequestParam String email) {

        log.info("비밀번호 재설정 요청 API 호출: {}", email);

        try {
            authService.requestPasswordReset(email);

            return ResponseEntity.ok(
                    ApiResponse.success("비밀번호 재설정 이메일이 발송되었습니다.", "SUCCESS")
            );

        } catch (Exception e) {
            log.error("비밀번호 재설정 요청 실패: {} - {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 현재 사용자 정보 조회 API
     * GET /api/auth/me
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(
            Authentication authentication) {

        if (authentication != null && authentication.isAuthenticated()) {
            String email = authentication.getName();
            log.debug("현재 사용자 정보 조회 API 호출: {}", email);

            try {
                // 사용자 정보 조회 로직은 UserController에서 처리
                return ResponseEntity.ok(
                        ApiResponse.success("현재 사용자 정보입니다.",
                                UserResponse.builder()
                                        .email(email)
                                        .build())
                );

            } catch (Exception e) {
                log.error("사용자 정보 조회 실패: {} - {}", email, e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(ApiResponse.failure("사용자 정보 조회 중 오류가 발생했습니다."));
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiResponse.failure("인증되지 않은 사용자입니다."));
    }

    // ========== 유틸리티 메서드들 ==========

    /**
     * Refresh Token 추출 (여러 소스에서)
     */
    private String extractRefreshToken(String bodyToken, HttpServletRequest request) {
        // 1. Request Body에서 추출
        if (bodyToken != null && !bodyToken.isEmpty()) {
            return bodyToken;
        }

        // 2. 쿠키에서 추출
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        // 3. Authorization 헤더에서 추출
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        return null;
    }

    /**
     * 쿠키에 토큰 추가
     */
    private void addTokenToCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // HTTPS 사용 시 true로 변경
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    /**
     * 쿠키에서 토큰 제거
     */
    private void removeTokenFromCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, "");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}