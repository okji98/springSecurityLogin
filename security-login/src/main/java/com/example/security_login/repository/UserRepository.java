package com.example.security_login.repository;

import com.example.security_login.entity.AuthProvider;
import com.example.security_login.entity.User;
import com.example.security_login.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * 이메일로 사용자 찾기
     */
    Optional<User> findByEmail(String email);

    /**
     * 이메일 존재 여부 확인
     */
    boolean existsByEmail(String email);

    /**
     * OAuth2 제공자와 제공자 ID로 사용자 찾기
     */
    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);

    /**
     * 이름으로 사용자 검색 (관리자용)
     */
    List<User> findByNameContainingIgnoreCase(String name);

    /**
     * 활성화된 사용자만 조회
     */
    List<User> findByEnabledTrue();

    /**
     * 특정 권한을 가진 사용자 조회
     */
    @Query("SELECT u FROM User u WHERE u.role = :role")
    List<User> findByRole(@Param("role") Role role);

    /**
     * OAuth2 사용자들만 조회
     */
    @Query("SELECT u FROM User u WHERE u.provider != 'LOCAL'")
    List<User> findOAuth2Users();

    /**
     * 일반 로그인 사용자들만 조회
     */
    @Query("SELECT u FROM User u WHERE u.provider = 'LOCAL'")
    List<User> findLocalUsers();

    /**
     * 이메일과 제공자로 사용자 존재 여부 확인
     */
    boolean existsByEmailAndProvider(String email, AuthProvider provider);

    /**
     * 전화번호로 사용자 찾기
     */
    Optional<User> findByPhoneNumber(String phoneNumber);

    /**
     * 사용자 통계 조회
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.provider = :provider")
    long countByProvider(@Param("provider") AuthProvider provider);

    /**
     * 최근 가입한 사용자들 조회 (관리자용)
     */
    @Query("SELECT u FROM User u ORDER BY u.createdAt DESC")
    List<User> findRecentUsers();
}
