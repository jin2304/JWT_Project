package com.example.jwt_project.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * LoginFilter
 * 코드 작성자: 서진영(jin2304)
 * 코드 설명: LoginFilter 클래스는 사용자 로그인 시, 사용자 인증을 처리하는 커스텀 필터, UsernamePasswordAuthenticationFilter를 상속받음.
 *           attemptAuthentication() 메서드에서 사용자의 username과 password를 추출하여 토큰으로 만든 후,
 *           스프링 시큐리티의 AuthenticationManager를 통해 인증을 시도.
 *
 * 코드 주요 기능:
 * - attemptAuthentication() 메서드는 UsernamePasswordAuthenticationFilter 클래스의 메서드로, 사용자가 로그인 시도를 할 때 호출됨
 * - attemptAuthentication() 메서드에서 AuthenticationManager를 통해 사용자 인증을 시도, 인증이 성공하면 Authentication 객체 반환
 *
 * 코드 작성일: 2024.07.16 ~ 2024.07.16
 *
 */
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    /**
     * 사용자의 로그인 인증 시도
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException  {

        //클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }
}