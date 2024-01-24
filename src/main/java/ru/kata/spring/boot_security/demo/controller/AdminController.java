package ru.kata.spring.boot_security.demo.controller;

import java.util.List;
import javax.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public ModelAndView displayAllUsers(Model model) {
        List<Role> availableRoles = userService.getAllRoles();
        model.addAttribute("availableRoles", availableRoles);
        model.addAttribute("userList", userService.getAllUsersWithRoles());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserByEmail(username);
        model.addAttribute("userinfo", user);
        model.addAttribute("title", user.getFirstName() + " panel");
        model.addAttribute("user", new User());
        return new ModelAndView("admin");
    }
}

