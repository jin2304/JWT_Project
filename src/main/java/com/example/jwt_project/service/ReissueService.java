package com.example.jwt_project.service;


import com.example.jwt_project.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ReissueService {

    private final JWTUtil jwtUtil;

    @Autowired
    public ReissueService(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
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

        //refresh 토큰이 유효한 경우 반환
        return refresh;
    }



    /**
     * 새로운 Access 토큰 생성 메서드
     */
    public String createNewAccessToken(String refresh) {
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);
        return jwtUtil.createJwt("access", username, role, 10*60*1000L); //유효 시간: 10분(10 * 60 * 1초)
    }


    /**
     * 새로운 Refresh 토큰 생성 메서드
     */
    public String createNewRefreshToken(String refresh) {
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);
        return jwtUtil.createJwt("refresh", username, role, 24*60*60*1000L); //유효 시간: 24시간(24 * 60 * 60 * 1초)
    }
}
