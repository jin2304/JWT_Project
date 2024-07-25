package com.example.jwt_project.repository;

import com.example.jwt_project.document.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User, String> {
    //사용자 이름 붕복 확인
    Boolean existsByUsername(String username);

    //username으로 DB 회원 조회
    User findByUsername(String username);
}
