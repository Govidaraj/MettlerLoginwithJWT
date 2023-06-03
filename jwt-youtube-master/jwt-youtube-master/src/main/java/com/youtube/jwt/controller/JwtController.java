package com.youtube.jwt.controller;

import com.youtube.jwt.dao.SessionRepo;
import com.youtube.jwt.entity.JwtRequest;
import com.youtube.jwt.entity.JwtResponse;
import com.youtube.jwt.entity.Session;
import com.youtube.jwt.service.JwtService;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
public class JwtController {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private SessionRepo sessionRepository;

    @PostMapping({"/authenticate"})
    public JwtResponse createJwtToken(@RequestBody JwtRequest jwtRequest) throws Exception {
        JwtResponse jwtResponse = jwtService.createJwtToken(jwtRequest);

        Optional<Session> optionalSession = sessionRepository.findBySessionId(jwtResponse.getJwtToken());
        if (optionalSession.isPresent()) {
            Session session = optionalSession.get();
            jwtResponse.setSessionId(session.getId());
        }

        return jwtResponse;
    }
}

