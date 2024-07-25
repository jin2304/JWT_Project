package com.example.jwt_project.controller;


import com.example.jwt_project.document.User;
import com.example.jwt_project.dto.JoinDTO;
import com.example.jwt_project.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * 회원 가입
     */
    @PostMapping("/join")
    public String join(@RequestBody JoinDTO joinDTO) {
        System.out.println("join username: " + joinDTO.getUsername());
        User user = userService.createUser(joinDTO);
        System.out.println("join user: " + user);
        return "join ok";
    }
}
