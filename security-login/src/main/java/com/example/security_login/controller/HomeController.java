package com.example.security_login.controller;

import com.example.security_login.entity.User;
import com.example.security_login.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
public class HomeController {

    private final UserService userService;

    /**
     * 메인 페이지
     * GET /
     */
    @GetMapping("/")
    public String index(Authentication authentication, Model model) {
        log.debug("메인 페이지 요청");

        // 인증된 사용자라면 홈으로 리다이렉트
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/home";
        }

        // 인증되지 않은 사용자는 랜딩 페이지 표시
        model.addAttribute("pageTitle", "Welcome to Security Login");
        return "index";
    }

    /**
     * 로그인 페이지
     * GET /login
     */
    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            @RequestParam(value = "message", required = false) String message,
            Authentication authentication,
            Model model) {

        log.debug("로그인 페이지 요청");

        // 이미 로그인된 사용자는 홈으로 리다이렉트
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/home";
        }

        // 에러 메시지 처리
        if (error != null) {
            switch (error) {
                case "true":
                    model.addAttribute("errorMessage", "이메일 또는 비밀번호가 올바르지 않습니다.");
                    break;
                case "credentials":
                    model.addAttribute("errorMessage", "로그인 정보를 확인해주세요.");
                    break;
                case "oauth2":
                    model.addAttribute("errorMessage", "소셜 로그인 중 오류가 발생했습니다.");
                    break;
                case "oauth2_processing_error":
                    model.addAttribute("errorMessage", message != null ? message : "소셜 로그인 처리 중 오류가 발생했습니다.");
                    break;
                default:
                    model.addAttribute("errorMessage", "로그인 중 오류가 발생했습니다.");
            }
        }

        // 로그아웃 메시지 처리
        if (logout != null) {
            model.addAttribute("successMessage", "성공적으로 로그아웃되었습니다.");
        }

        model.addAttribute("pageTitle", "로그인");
        return "login";
    }

    /**
     * 회원가입 페이지
     * GET /register
     */
    @GetMapping("/register")
    public String registerPage(
            @RequestParam(value = "error", required = false) String error,
            Authentication authentication,
            Model model) {

        log.debug("회원가입 페이지 요청");

        // 이미 로그인된 사용자는 홈으로 리다이렉트
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/home";
        }

        // 에러 메시지 처리
        if ("validation".equals(error)) {
            model.addAttribute("errorMessage", "입력값을 확인해주세요.");
        }

        model.addAttribute("pageTitle", "회원가입");
        return "register";
    }

    /**
     * 홈 페이지 (로그인 후)
     * GET /home
     */
    @GetMapping("/home")
    public String homePage(Authentication authentication, Model model) {
        log.debug("홈 페이지 요청");

        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        String email = authentication.getName();

        // 사용자 정보 조회
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            model.addAttribute("user", user);
            model.addAttribute("welcomeMessage", user.getName() + "님, 환영합니다!");

            // 사용자 유형별 메시지
            String providerMessage = switch (user.getProvider()) {
                case GOOGLE -> "Google 계정으로 로그인하셨습니다.";
                case KAKAO -> "카카오 계정으로 로그인하셨습니다.";
                case NAVER -> "네이버 계정으로 로그인하셨습니다.";
                default -> "일반 계정으로 로그인하셨습니다.";
            };
            model.addAttribute("providerMessage", providerMessage);
        }

        model.addAttribute("pageTitle", "홈");
        return "home";
    }

    /**
     * 프로필 페이지
     * GET /profile
     */
    @GetMapping("/profile")
    public String profilePage(Authentication authentication, Model model) {
        log.debug("프로필 페이지 요청");

        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        String email = authentication.getName();

        // 사용자 정보 조회
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            model.addAttribute("user", user);

            // OAuth2 사용자는 비밀번호 변경 불가
            model.addAttribute("canChangePassword", user.getProvider().name().equals("LOCAL"));
        } else {
            model.addAttribute("errorMessage", "사용자 정보를 찾을 수 없습니다.");
            return "redirect:/login";
        }

        model.addAttribute("pageTitle", "프로필");
        return "profile";
    }

    /**
     * 관리자 페이지
     * GET /admin
     */
    @GetMapping("/admin")
    public String adminPage(Authentication authentication, Model model) {
        log.debug("관리자 페이지 요청");

        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        // 관리자 권한 확인은 Spring Security에서 처리됨

        // 사용자 통계 조회
        try {
            var userStats = userService.getUserStatistics();
            model.addAttribute("userStats", userStats);

            // 최근 가입 사용자들 (선택사항)
            var recentUsers = userService.getAllUsers(); // 실제로는 최근 사용자만 조회
            model.addAttribute("recentUsers", recentUsers);

        } catch (Exception e) {
            log.error("관리자 페이지 데이터 조회 실패", e);
            model.addAttribute("errorMessage", "데이터 조회 중 오류가 발생했습니다.");
        }

        model.addAttribute("pageTitle", "관리자");
        return "admin";
    }

    /**
     * 접근 거부 페이지
     * GET /access-denied
     */
    @GetMapping("/access-denied")
    public String accessDeniedPage(Model model) {
        log.debug("접근 거부 페이지 요청");

        model.addAttribute("pageTitle", "접근 거부");
        model.addAttribute("errorMessage", "해당 페이지에 접근할 권한이 없습니다.");
        return "error/403";
    }

    /**
     * 에러 페이지
     * GET /error
     */
    @GetMapping("/error")
    public String errorPage(Model model) {
        log.debug("에러 페이지 요청");

        model.addAttribute("pageTitle", "오류");
        model.addAttribute("errorMessage", "요청을 처리하는 중 오류가 발생했습니다.");
        return "error/500";
    }

    /**
     * 도움말 페이지
     * GET /help
     */
    @GetMapping("/help")
    public String helpPage(Model model) {
        log.debug("도움말 페이지 요청");

        model.addAttribute("pageTitle", "도움말");
        return "help";
    }

    /**
     * 이용약관 페이지
     * GET /terms
     */
    @GetMapping("/terms")
    public String termsPage(Model model) {
        log.debug("이용약관 페이지 요청");

        model.addAttribute("pageTitle", "이용약관");
        return "terms";
    }

    /**
     * 개인정보처리방침 페이지
     * GET /privacy
     */
    @GetMapping("/privacy")
    public String privacyPage(Model model) {
        log.debug("개인정보처리방침 페이지 요청");

        model.addAttribute("pageTitle", "개인정보처리방침");
        return "privacy";
    }
}