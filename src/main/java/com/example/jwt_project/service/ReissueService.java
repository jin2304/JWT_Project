package com.example.jwt_project.service;


import com.example.jwt_project.entity.RefreshEntity;
import com.example.jwt_project.jwt.JWTUtil;
import com.example.jwt_project.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class ReissueService {

    private final JWTUtil jwtUtil;
    public final RefreshRepository refreshRepository;

    @Autowired
    public ReissueService(JWTUtil jwtUtil, RefreshRepository refreshRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }



    /**
     * refresh 토큰을 검증하고 새로운 access, refresh 토큰을 반환하는 메서드
     */
    public String[] reissueTokens(String refresh) {
        // refresh 토큰 유효성 검사
        refresh = validateToken(refresh);

        // 토큰이 유효한 경우
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // 새로운 access 토큰 및 refresh 토큰 생성
        String newAccess = jwtUtil.createJwt("access", username, role, 10*60*1000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 24*60*60*1000L);

        // 기존의 refresh 토큰 삭제 후, 새 refresh 토큰 저장
        refreshRepository.deleteByRefresh(refresh);
        saveRefreshEntity(username, newRefresh, 24 * 60 * 60 * 1000L);

        return new String[]{newAccess, newRefresh};
    }


    /**
     *  refresh 토큰의 유효성 검사 메서드
     */
    public String validateToken(String refresh) {

        //refresh 토큰이 빈값인지 확인
        if (refresh == null) {
            throw new IllegalArgumentException("refresh token null");
        }

        //refresh 토큰 만료시간 확인
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException("refresh token expired");
        }

        //refresh 토큰인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            throw new IllegalArgumentException("invalid refresh token");
        }

        //DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            throw new IllegalArgumentException("invalid refresh token");
        }

        //refresh 토큰이 유효한 경우 반환
        return refresh;
    }


    /**
     *  DB에 refresh 토큰 저장 메서드
     */
    private void saveRefreshEntity(String username, String refresh, Long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }





}
