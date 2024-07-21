package com.example.jwt_project.controller;


import com.example.jwt_project.jwt.JWTUtil;
import com.example.jwt_project.service.ReissueService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;



/**
 * ReissueController
 *
 * 코드 작성자:
 *   - 서진영(jin2304)
 *
 * 코드 설명:
 *   - ReissueController는 refresh 토큰을 통해 새로운 access 토큰과 refresh 토큰 재발급을 처리하는 컨트롤러.
 *   - refresh 토큰을 쿠키에서 가져와 유효성 검사.
 *   - refresh 토큰이 유효한 경우, 새로운 access 토큰과 refresh 토큰을 생성하여 각각 응답 헤더와 응답 쿠키에 설정.
 *
 * 코드 주요 기능:
 *   - /reissue 엔드포인트를 처리하며, refresh 토큰을 검증하고, 새로운 access 토큰과 refresh 토큰을 발급.
 *
 * 코드 작성일:
 *   - 2024.07.21 ~ 2024.07.22
 */
@Controller
@ResponseBody
public class ReissueController {

    public final ReissueService reissueService;

    @Autowired
    public ReissueController(ReissueService reissueService) {
        this.reissueService = reissueService;
    }



    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // refresh 토큰 가져오기
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals("refresh")){
                refresh = cookie.getValue();
            }
        }



        // refresh 토큰 유효성 검사
        try {
            String[] tokens = reissueService.reissueTokens(refresh);
            String newAccess = tokens[0];
            String newRefresh = tokens[1];

            // 응답헤더에 새로 발급된 access 토큰, 응답쿠키에 새로 발급된 refresh 토큰 설정
            response.setHeader("access", newAccess);
            response.addCookie(createCookie("refresh", newRefresh));
            return new ResponseEntity<>(HttpStatus.OK);

        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
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
}
