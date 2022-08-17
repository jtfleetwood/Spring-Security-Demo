package com.example.demo.services;

import com.example.demo.models.User;
import com.example.demo.repos.UserRepo;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
// Service layer implementation for users.
public class UserServiceImpl implements UserService, UserDetailsService {

    // User Repo to interact with DB.
    private final UserRepo userRepo;

    // Password encoder bean used to encrypt passwords when storing.
    private final PasswordEncoder passwordEncoder;


    // Saving user to DB.
    @Override
    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    // Getting user by username.
    @Override
    public User getUser(String username) {
        Optional<User> foundUser = userRepo.findByUsername(username);

        if (foundUser.isPresent()) {
            return foundUser.get();
        }

        throw new RuntimeException();
    }

    // Getting list of users.
    @Override
    public List<User> getUsers() {

        return userRepo.findAll();
    }


    // Finding a user by username in our DB and providing an instance of UserDetails to be used by Spring Security in Authentication process.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepo.findByUsername(username);
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        if (user.isPresent()) {
            return new org.springframework.security.core.userdetails.User(user.get().getUsername(), user.get().getPassword(), authorities);
        }

        throw new RuntimeException();
    }
}
