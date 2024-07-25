package com.example.jwt_project.jwt;


import com.example.jwt_project.document.Refresh;
import com.example.jwt_project.dto.LoginDTO;
import com.example.jwt_project.repository.RefreshRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

/**
 * LoginFilter 클래스
 * 코드 작성자: 서진영(jin2304)
 * 코드 설명: LoginFilter 클래스는 사용자 로그인 시, 사용자 인증을 처리하는 커스텀 필터, UsernamePasswordAuthenticationFilter를 상속받음.
 *           attemptAuthentication() 메서드에서 사용자의 username과 password를 추출하여 토큰으로 만든 후, 스프링 시큐리티의 AuthenticationManager를 통해 인증을 시도.
 *           로그인 성공(인증 성공)시 2개의 JWT(access, refresh 토큰) 발급, 로그인 실패 시 에러 코드 반환.
 *
 * 코드 주요 기능:
 * -attemptAuthentication(): 사용자가 로그인 시 호출되며, 로그인 시도를 처리함. AuthenticationManager를 통해 사용자 인증을 시도.
 * -successfulAuthentication(): 로그인 성공 시 JWT를 생성하여 응답 헤더에 추가.
 * -unsuccessfulAuthentication(): 로그인 실패 시 401 응답 코드를 반환.
 *
 * 코드 작성일: 2024.07.16 ~ 2024.07.22
 */
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    /**
     * 사용자의 로그인 인증 처리
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException  {

        // 1) Form-data 로그인 방식
        //클라이언트 요청에서 username, password 추출
        //String username = obtainUsername(request);
        //String password = obtainPassword(request);


        // 2) Json 로그인 방식
        LoginDTO loginDTO = new LoginDTO();
        try {
            ObjectMapper objectMapper = new ObjectMapper();  // ObjectMapper: Jackson 라이브러리로, 이를 사용하여 JSON 형식의 데이터를 Java 객체로 변환
            ServletInputStream inputStream = request.getInputStream();   // 클라이언트 요청 본문(body)을 읽기 위해 InputStream 가져오기
            String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);  // InputStream을 문자열로 변환 (UTF-8 인코딩 사용)
            loginDTO = objectMapper.readValue(messageBody, LoginDTO.class);  // JSON 형식의 문자열(messageBody)을 LoginDTO 객체로 변환

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        System.out.println(loginDTO.getUsername());

        String username = loginDTO.getUsername();
        String password = loginDTO.getPassword();

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }



    /**
     * 로그인 성공 시 실행하는 메소드(여기서 2개의 JWT 발급)
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        // 사용자 이름 가져옴
        String username = authentication.getName();

        // 사용자의 권한 정보를 가져옴
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities(); //사용자의 권한 정보를 Collection 형태로 가져옴
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator(); //권한 정보를 순회하기 위한 Iterator 생성
        GrantedAuthority auth = iterator.next();  //Iterator에서 첫 번째 권한 객체를 가져옴
        String role = auth.getAuthority();

        //2개의 JWT(access, refresh) 토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 10*60*1000L);      //유효 시간: 10분(10 * 60 * 1초)
        String refresh = jwtUtil.createJwt("refresh", username, role, 24*60*60*1000L); //유효 시간: 24시간(24 * 60 * 60 * 1초)

        //Refresh 토큰을 DB에 저장
        saveRefreshEntity(username, refresh, 24*60*60*1000L);

        //응답 헤더에 JWT 추가
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }



    /**
     * 로그인 실패 시 실행하는 메소드
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        //로그인 실패시 401 응답 코드 반환
        response.setStatus(401);
    }


    /**
     *  쿠키 생성 메소드
     */
    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);  // 쿠키의 생명주기 설정
        //cookie.setSecure(true);    // HTTPS 에서만 쿠키 전송 설정
        //cookie.setPath("/");       // 쿠키의 유효 경로 설정(쿠키가 적용될 범위)
        cookie.setHttpOnly(true);    // 클라이언트(프론트)에서 자바스크립트로 해당 쿠키를 접근할수없도록 설정

        return cookie;
    }


    /**
     *  DB에 refresh 토큰 저장 메서드
     */
    private void saveRefreshEntity(String username, String refresh, Long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        Refresh refreshDocument = new Refresh();
        refreshDocument.setUsername(username);
        refreshDocument.setRefresh(refresh);
        refreshDocument.setExpiration(date.toString());

        refreshRepository.save(refreshDocument);
    }

}