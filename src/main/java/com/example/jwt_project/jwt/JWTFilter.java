package com.example.jwt_project.jwt;

import com.example.jwt_project.dto.CustomUserDetails;
import com.example.jwt_project.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/**
 * JWTFilter 클래스
 * 코드 작성자: 서진영(jin2304)
 * 코드 설명: JWTFilter 클래스는 JWT 기반 인증을 처리하는 커스텀 필터, OncePerRequestFilter를 상속받음.
 *           doFilterInternal() 메서드에서 요청 헤더에서 JWT를 추출하고, 토큰의 유효성을 검사하여 인증 정보를 설정함.
 *           유효한 JWT 토큰이 있는 경우, 해당 토큰에서 사용자 정보를 추출하여 Spring Security의 인증 컨텍스트에 설정함.
 *           토큰이 유효하지 않거나 없을 경우, 필터 체인을 통해 다음 필터로 요청을 전달함.
 *
 * 코드 주요 기능:
 * - doFilterInternal(): 요청이 들어올 때마다 호출되며, JWT 토큰의 유효성을 검사하고 사용자 인증을 처리함.
 *                       유효하지 않은 토큰일 경우, 요청을 그대로 필터 체인에 전달함.
 *
 * 코드 작성일: 2024.07.18 ~ 2024.07.18
 */
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");


        //토큰이 존재하는지 검증
        if(authorization==null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null");
            filterChain.doFilter(request, response);
            return; //조건이 해당되면 메소드 종료 (필수)
        }
        System.out.println("authorization now");
        String token = authorization.split(" ")[1];


        //토큰 검증 시간 검증
        if(jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            return; //조건이 해당되면 메소드 종료 (필수)
        }



        //토큰이 유효한 경우
        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("tempPassword");
        userEntity.setRole(role);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        //요청이 들어올 때 잠시 동안 세션에 저장
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
