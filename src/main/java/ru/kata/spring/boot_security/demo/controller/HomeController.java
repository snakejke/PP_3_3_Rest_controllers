package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

@RestController
@RequestMapping("/")
public class HomeController {

    private final UserService userService;

    @Autowired
    public HomeController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = {"/", "/login"})
    public ModelAndView loginForm() {
        return new ModelAndView("login");
    }

    @GetMapping("/user")
    public ModelAndView getUserInfo(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserByEmail(username);
        model.addAttribute("userinfo", user);
        model.addAttribute("title", user.getFirstName() + " panel");
        return new ModelAndView("user");
    }
}

