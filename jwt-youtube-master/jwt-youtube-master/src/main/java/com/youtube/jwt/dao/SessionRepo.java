package com.youtube.jwt.dao;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.youtube.jwt.entity.Session;

@Repository
public interface SessionRepo extends JpaRepository<Session, Long> {

    Optional<Session> findBySessionId(String sessionId);
}
