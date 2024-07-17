package com.example.jwt_project.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;


/**
 * JWTUti 클래스
 * 코드 작성자: 서진영(jin2304)
 * 코드 설명: JWTUtil 클래스는 JWT(JSON Web Token)의 생성, 검증, 파싱을 위한 유틸리티 메서드를 제공함.
 * 코드 주요 기능: JWT 생성, JWT 검증(사용자 이름 추출 검증, 사용자 역할 추출 검증, 만료 여부 검증)
 * 코드 작성일: 2024.07.17 ~ 2024.07.17
 *
 */
 public class JWTUtil {

    private SecretKey secretKey;


    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {
        //주입된 secret 값을 사용하여 SecretKey 객체를 생성
        //secretKey = new SecretKeySpec(secret.getBytes(인코딩 방식), 서명 알고리즘);
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    /**
     *  JWT 생성
     */
    public String createJwt(String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("username", username) // "username" 클레임을 설정
                .claim("role", role) // "role" 클레임을 설정
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 시간을 발행 시간으로 설정
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 만료 시간을 설정
                .signWith(secretKey) // secretKey로 JWT를 서명
                .compact(); // JWT를 직렬화하여 압축된 문자열로 반환
    }



    /**
     *  JWT에서 사용자 이름 추출하여 검증
     */
    public String getUsername(String token){
        return Jwts.parser()
                .verifyWith(secretKey) //secretKey로 JWT 서명을 검증
                .build()
                .parseSignedClaims(token)  //서명이 검증된 JWT를 파싱하여 JWT 클레임 객체 반환 (클레임: 페이로드의 속성들)
                .getPayload()              //반환된 JWT 클레임 객체에서 페이로드 부분 가져옴
                .get("username", String.class); // "username" 클레임 값을 문자열로 반환
    }



    /**
     *  JWT에서 사용자 역할 추출하여 검증
     */
    public String getRole(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }



    /**
     *  JWT에서 만료 여부 검증
     */
    public Boolean isExpired(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration() // 만료 시간을 가져옴.
                .before(new Date()); // 현재 시간과 비교하여 만료 여부를 반환
    }
}
