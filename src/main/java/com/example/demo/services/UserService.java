package com.example.demo.services;

import com.example.demo.models.User;

import java.util.List;
import java.util.Optional;

// Simple service layer for users.
public interface UserService {
    User saveUser(User user);
    User getUser(String username);
    List<User> getUsers();

}
