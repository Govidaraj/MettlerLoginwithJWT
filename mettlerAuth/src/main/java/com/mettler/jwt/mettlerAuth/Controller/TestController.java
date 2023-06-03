package com.mettler.jwt.mettlerAuth.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
@RequestMapping("api/")
public class TestController {

    @GetMapping("CheckAuth")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_PATENT','ROLE_STAFF')")
    public ResponseEntity<?> checkRole(){
        System.out.println("Welcome");
        return ResponseEntity.ok("Role is working");
    }
}