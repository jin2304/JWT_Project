package com.example.jwt_project.service;

import com.example.jwt_project.document.User;
import com.example.jwt_project.dto.JoinDTO;

import java.util.List;

public interface UserService {
    User createUser(JoinDTO joinDTO);

    List<User> getAllUsers();

    User getUserById(String id);

    void deleteUserById(String id);
}
