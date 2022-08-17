package com.example.demo.models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

// Below is basic user model just for testing purposes.
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
// Using users as table name, 'user' is a reserved word in most data manipulation languages.
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;
}
