package com.youtube.jwt.controller;

import com.youtube.jwt.entity.User;
import com.youtube.jwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @PostConstruct
    public void initRoleAndUser() {
        userService.initRoleAndUser();
    }

    @PostMapping({"/registerNewUser"})
    public User registerNewUser(@RequestBody User user) {
        return userService.registerNewUser(user);
    }

//    @GetMapping({"/forAdmin"})
//    @PreAuthorize("hasRole('Admin')")
//    public String forAdmin(){
//        return "Admin login successfully";
//    }
    @Autowired
    @GetMapping("/forAdmin")
     public String loginUser(@ModelAttribute User user, HttpServletRequest request,HttpServletResponse response) {
    if((userService.findByUserFirstNameAndUserPassword(user.getUserFirstName(), user.getUserPassword())!=null)) {
        Cookie loginCookie=new Cookie("mouni",user.getUserName());
        loginCookie.setMaxAge(30*5);
        response.addCookie(loginCookie);
    return "homepage";
    }
    else {
        request.setAttribute("error", "Invalid Username or Password");
        request.setAttribute("mode", "MODE_LOGIN");
        return "welcomepage";
    }
    }

    @GetMapping("/forUser")
    @PreAuthorize("hasRole('User')")
    public String forUser(){
        return "User login successfully";
    }
}
