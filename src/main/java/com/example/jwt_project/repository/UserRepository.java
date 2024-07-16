package com.example.jwt_project.repository;

import com.example.jwt_project.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    //사용자 이름 붕복 확인
    Boolean existsByUsername(String username);
}
