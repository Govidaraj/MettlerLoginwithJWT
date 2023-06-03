//package com.mettler.jwt.mettlerAuth.repository;
//
//import java.time.LocalDateTime;
//import java.util.List;
//import java.util.Optional;
//
//import org.springframework.data.jpa.repository.JpaRepository;
//
//import com.mettler.jwt.mettlerAuth.Models.Session;
//
//public interface SessionRepository extends JpaRepository<Session, Long> {
//    Optional<Session> findBySessionId(String sessionId);
//    List<Session> findByUsername(String username);
//    void deleteByExpireTimeBefore(LocalDateTime expireTime);
//}