package com.example.security_login.controller;

import com.example.security_login.dto.*;
import com.example.security_login.entity.User;
import com.example.security_login.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * 현재 사용자 정보 조회 API
     * GET /api/users/me
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("인증되지 않은 사용자입니다."));
        }

        String email = authentication.getName();
        log.debug("현재 사용자 정보 조회 API 호출: {}", email);

        try {
            Optional<User> userOpt = userService.findByEmail(email);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponse.failure("사용자를 찾을 수 없습니다."));
            }

            UserResponse userResponse = UserResponse.from(userOpt.get());
            return ResponseEntity.ok(
                    ApiResponse.success("현재 사용자 정보입니다.", userResponse)
            );

        } catch (Exception e) {
            log.error("사용자 정보 조회 실패: {} - {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("사용자 정보 조회 중 오류가 발생했습니다."));
        }
    }

    /**
     * 사용자 프로필 업데이트 API
     * PUT /api/users/me
     */
    @PutMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> updateProfile(
            @Valid @RequestBody UserUpdateRequest updateRequest,
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("인증되지 않은 사용자입니다."));
        }

        String email = authentication.getName();
        log.info("프로필 업데이트 API 호출: {}", email);

        try {
            // TODO: UserService에 updateProfile 메서드 구현 필요
            // UserResponse updatedUser = userService.updateProfile(email, updateRequest);

            return ResponseEntity.ok(
                    ApiResponse.success("프로필이 성공적으로 업데이트되었습니다.", null)
            );

        } catch (Exception e) {
            log.error("프로필 업데이트 실패: {} - {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 비밀번호 변경 API
     * PUT /api/users/me/password
     */
    @PutMapping("/me/password")
    public ResponseEntity<ApiResponse<String>> changePassword(
            @Valid @RequestBody PasswordChangeRequest passwordRequest,
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("인증되지 않은 사용자입니다."));
        }

        String email = authentication.getName();
        log.info("비밀번호 변경 API 호출: {}", email);

        // 새 비밀번호 확인
        if (!passwordRequest.getNewPassword().equals(passwordRequest.getConfirmNewPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.failure("새 비밀번호가 일치하지 않습니다."));
        }

        try {
            userService.changePassword(
                    email,
                    passwordRequest.getCurrentPassword(),
                    passwordRequest.getNewPassword()
            );

            return ResponseEntity.ok(
                    ApiResponse.success("비밀번호가 성공적으로 변경되었습니다.", "SUCCESS")
            );

        } catch (Exception e) {
            log.error("비밀번호 변경 실패: {} - {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 사용자 계정 비활성화 API
     * DELETE /api/users/me
     */
    @DeleteMapping("/me")
    public ResponseEntity<ApiResponse<String>> deactivateAccount(
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("인증되지 않은 사용자입니다."));
        }

        String email = authentication.getName();
        log.info("계정 비활성화 API 호출: {}", email);

        try {
            Optional<User> userOpt = userService.findByEmail(email);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponse.failure("사용자를 찾을 수 없습니다."));
            }

            userService.deactivateUser(userOpt.get().getId());

            return ResponseEntity.ok(
                    ApiResponse.success("계정이 성공적으로 비활성화되었습니다.", "SUCCESS")
            );

        } catch (Exception e) {
            log.error("계정 비활성화 실패: {} - {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("계정 비활성화 중 오류가 발생했습니다."));
        }
    }

    // ========== 관리자 전용 API ==========

    /**
     * 모든 사용자 조회 API (관리자 전용)
     * GET /api/users
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        log.info("모든 사용자 조회 API 호출 (관리자)");

        try {
            List<UserResponse> users = userService.getAllUsers();

            return ResponseEntity.ok(
                    ApiResponse.success("사용자 목록 조회 성공", users)
            );

        } catch (Exception e) {
            log.error("사용자 목록 조회 실패: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("사용자 목록 조회 중 오류가 발생했습니다."));
        }
    }

    /**
     * 사용자 검색 API (관리자 전용)
     * GET /api/users/search?name={name}
     */
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<UserResponse>>> searchUsers(
            @RequestParam String name) {

        log.info("사용자 검색 API 호출 (관리자): {}", name);

        try {
            List<UserResponse> users = userService.searchUsersByName(name);

            return ResponseEntity.ok(
                    ApiResponse.success("사용자 검색 성공", users)
            );

        } catch (Exception e) {
            log.error("사용자 검색 실패: {} - {}", name, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("사용자 검색 중 오류가 발생했습니다."));
        }
    }

    /**
     * 특정 사용자 정보 조회 API (관리자 전용)
     * GET /api/users/{userId}
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(
            @PathVariable Long userId) {

        log.info("사용자 정보 조회 API 호출 (관리자): {}", userId);

        try {
            Optional<User> userOpt = userService.findById(userId);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponse.failure("사용자를 찾을 수 없습니다."));
            }

            UserResponse userResponse = UserResponse.from(userOpt.get());
            return ResponseEntity.ok(
                    ApiResponse.success("사용자 정보 조회 성공", userResponse)
            );

        } catch (Exception e) {
            log.error("사용자 정보 조회 실패: {} - {}", userId, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("사용자 정보 조회 중 오류가 발생했습니다."));
        }
    }

    /**
     * 사용자 비활성화 API (관리자 전용)
     * PUT /api/users/{userId}/deactivate
     */
    @PutMapping("/{userId}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> deactivateUser(
            @PathVariable Long userId) {

        log.info("사용자 비활성화 API 호출 (관리자): {}", userId);

        try {
            userService.deactivateUser(userId);

            return ResponseEntity.ok(
                    ApiResponse.success("사용자가 성공적으로 비활성화되었습니다.", "SUCCESS")
            );

        } catch (Exception e) {
            log.error("사용자 비활성화 실패: {} - {}", userId, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 사용자 활성화 API (관리자 전용)
     * PUT /api/users/{userId}/activate
     */
    @PutMapping("/{userId}/activate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<String>> activateUser(
            @PathVariable Long userId) {

        log.info("사용자 활성화 API 호출 (관리자): {}", userId);

        try {
            userService.activateUser(userId);

            return ResponseEntity.ok(
                    ApiResponse.success("사용자가 성공적으로 활성화되었습니다.", "SUCCESS")
            );

        } catch (Exception e) {
            log.error("사용자 활성화 실패: {} - {}", userId, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.failure(e.getMessage()));
        }
    }

    /**
     * 사용자 통계 조회 API (관리자 전용)
     * GET /api/users/statistics
     */
    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Long>>> getUserStatistics() {
        log.info("사용자 통계 조회 API 호출 (관리자)");

        try {
            Map<String, Long> statistics = userService.getUserStatistics();

            return ResponseEntity.ok(
                    ApiResponse.success("사용자 통계 조회 성공", statistics)
            );

        } catch (Exception e) {
            log.error("사용자 통계 조회 실패: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("사용자 통계 조회 중 오류가 발생했습니다."));
        }
    }
}

// ========== 추가 DTO 클래스 ==========

/**
 * 사용자 프로필 업데이트 요청 DTO
 */
class UserUpdateRequest {

    @jakarta.validation.constraints.NotBlank(message = "이름은 필수입니다.")
    @jakarta.validation.constraints.Size(min = 2, max = 20, message = "이름은 2자 이상 20자 이하여야 합니다.")
    private String name;

    @jakarta.validation.constraints.Pattern(
            regexp = "^01[016789]-\\d{3,4}-\\d{4}$",
            message = "올바른 전화번호 형식이 아닙니다. (예: 010-1234-5678)"
    )
    private String phoneNumber;

    // getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }
}