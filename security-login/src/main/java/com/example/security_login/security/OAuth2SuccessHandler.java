package com.example.security_login.security;

import com.example.security_login.entity.User;
import com.example.security_login.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;

    @Value("${app.oauth2.redirect-uri:http://localhost:8080/home}")
    private String redirectUri;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        try {
            // OAuth2 사용자 정보로 User 조회/생성
            User user = userService.processOAuth2User(oAuth2User, getRegistrationId(request));

            // JWT 토큰 생성
            String accessToken = jwtTokenProvider.generateAccessToken(user.getEmail());
            String refreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail());

            // Refresh Token을 데이터베이스에 저장
            userService.saveRefreshToken(user.getEmail(), refreshToken);

            // 쿠키에 토큰 저장
            addTokenToCookie(response, "access_token", accessToken, 3600); // 1시간
            addTokenToCookie(response, "refresh_token", refreshToken, 1209600); // 14일

            // 리다이렉트 URL 설정
            String targetUrl = determineTargetUrl(request, response, authentication, accessToken);

            log.info("OAuth2 로그인 성공: 사용자={}, 제공자={}",
                    user.getEmail(), user.getProvider());

            getRedirectStrategy().sendRedirect(request, response, targetUrl);

        } catch (Exception e) {
            log.error("OAuth2 로그인 처리 중 오류 발생", e);

            // 오류 발생 시 로그인 페이지로 리다이렉트
            String errorUrl = UriComponentsBuilder.fromUriString("/login")
                    .queryParam("error", "oauth2_processing_error")
                    .queryParam("message", URLEncoder.encode("소셜 로그인 처리 중 오류가 발생했습니다.", StandardCharsets.UTF_8))
                    .build().toUriString();

            getRedirectStrategy().sendRedirect(request, response, errorUrl);
        }
    }

    /**
     * 리다이렉트 URL 결정
     */
    private String determineTargetUrl(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication,
            String accessToken) {

        // 저장된 리다이렉트 URL이 있는지 확인
        String savedRedirectUri = getSavedRedirectUri(request);
        if (savedRedirectUri != null) {
            removeSavedRedirectUri(request, response);
            return savedRedirectUri;
        }

        // 기본 리다이렉트 URL에 토큰 추가 (선택사항)
        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", accessToken)
                .build().toUriString();
    }

    /**
     * OAuth2 제공자 ID 추출
     */
    private String getRegistrationId(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        if (requestUri.contains("/oauth2/code/")) {
            return requestUri.substring(requestUri.lastIndexOf("/") + 1);
        }
        return "unknown";
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
     * 저장된 리다이렉트 URI 조회
     */
    private String getSavedRedirectUri(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("redirect_uri".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * 저장된 리다이렉트 URI 제거
     */
    private void removeSavedRedirectUri(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = new Cookie("redirect_uri", "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}