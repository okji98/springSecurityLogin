package com.example.security_login.exception;

import com.example.security_login.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 커스텀 예외 처리
     */
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<?> handleCustomException(CustomException e, HttpServletRequest request) {
        log.warn("Custom Exception: {}", e.getMessage());

        // API 요청인 경우 JSON 응답
        if (isApiRequest(request)) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.failure(e.getMessage()));
        }

        // 웹 페이지 요청인 경우 에러 페이지로 리다이렉트
        ModelAndView mav = new ModelAndView("error");
        mav.addObject("errorMessage", e.getMessage());
        return ResponseEntity.badRequest().body(mav);
    }

    /**
     * 인증 예외 처리
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> handleAuthenticationException(AuthenticationException e, HttpServletRequest request) {
        log.warn("Authentication Exception: {}", e.getMessage());

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("인증에 실패했습니다.", e.getMessage()));
        }

        ModelAndView mav = new ModelAndView("redirect:/login?error=true");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mav);
    }

    /**
     * 잘못된 자격증명 예외 처리
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<?> handleBadCredentialsException(BadCredentialsException e, HttpServletRequest request) {
        log.warn("Bad Credentials Exception: {}", e.getMessage());

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.failure("이메일 또는 비밀번호가 올바르지 않습니다."));
        }

        ModelAndView mav = new ModelAndView("redirect:/login?error=credentials");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(mav);
    }

    /**
     * 접근 권한 예외 처리
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleAccessDeniedException(AccessDeniedException e, HttpServletRequest request) {
        log.warn("Access Denied Exception: {}", e.getMessage());

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiResponse.failure("접근 권한이 없습니다."));
        }

        ModelAndView mav = new ModelAndView("error/403");
        mav.addObject("errorMessage", "접근 권한이 없습니다.");
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(mav);
    }

    /**
     * 유효성 검증 예외 처리 (RequestBody)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationException(
            MethodArgumentNotValidException e) {
        log.warn("Validation Exception: {}", e.getMessage());

        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        return ResponseEntity.badRequest()
                .body(ApiResponse.failure("입력값 검증에 실패했습니다.", errors.toString()));
    }

    /**
     * 유효성 검증 예외 처리 (Form Data)
     */
    @ExceptionHandler(BindException.class)
    public ResponseEntity<?> handleBindException(BindException e, HttpServletRequest request) {
        log.warn("Bind Exception: {}", e.getMessage());

        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        if (isApiRequest(request)) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.failure("입력값 검증에 실패했습니다.", errors.toString()));
        }

        // 폼 페이지로 에러와 함께 리다이렉트
        ModelAndView mav = new ModelAndView("redirect:/register?error=validation");
        return ResponseEntity.badRequest().body(mav);
    }

    /**
     * 일반 예외 처리
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneralException(Exception e, HttpServletRequest request) {
        log.error("Unexpected Exception: ", e);

        if (isApiRequest(request)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("서버 내부 오류가 발생했습니다."));
        }

        ModelAndView mav = new ModelAndView("error/500");
        mav.addObject("errorMessage", "서버 내부 오류가 발생했습니다.");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(mav);
    }

    /**
     * API 요청인지 확인
     */
    private boolean isApiRequest(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        String acceptHeader = request.getHeader("Accept");

        return requestURI.startsWith("/api/") ||
                (acceptHeader != null && acceptHeader.contains("application/json"));
    }
}