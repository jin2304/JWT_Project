package com.example.jwt_project.document;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "User")
@Getter
@Setter
@ToString
@AllArgsConstructor  //기본 생성자 생성
@NoArgsConstructor   //모든 필드를 인자로 받는 생성자 생성
public class User {
    @Id
    private String _id;  //private String id;
    private String username;
    private String password;
    private String role;
}
