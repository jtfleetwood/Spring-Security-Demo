package com.example.demo.Bootstrap;

import com.example.demo.models.User;
import com.example.demo.repos.UserRepo;
import com.example.demo.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class BootstrapData implements CommandLineRunner {
    private final UserService userService;

    @Override
    public void run(String... args) throws Exception {
        User newUser1 = new User();
        newUser1.setPassword("jt1234");
        newUser1.setName("JT");
        newUser1.setUsername("jfleetw");

        User newUser2 = new User();
        newUser2.setPassword("tom1234");
        newUser2.setName("Tom");
        newUser2.setUsername("tfleetw");
        userService.saveUser(newUser1);
        userService.saveUser(newUser2);
    }
}
