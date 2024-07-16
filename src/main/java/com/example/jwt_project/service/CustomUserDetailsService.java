package com.example.jwt_project.service;

import com.example.jwt_project.dto.CustomUserDetails;
import com.example.jwt_project.entity.UserEntity;
import com.example.jwt_project.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //DB 회원 조회
        UserEntity userEntity = userRepository.findByUsername(username);
        if(userEntity!=null){
            //UserDetails에 담아서 return하면 AutneticationManager가 검증
            return new CustomUserDetails(userEntity);
        }
        return null;
    }
}
