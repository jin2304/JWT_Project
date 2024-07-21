package com.example.jwt_project.repository;

import com.example.jwt_project.entity.RefreshEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    //refresh 토큰 존재 여부 확인 메서드
    Boolean existsByRefresh(String refresh);

    //refresh 토큰 삭제 메서드
    @Transactional
    void deleteByRefresh(String refresh);
}
