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
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AdminController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public String displayAllUsers(Model model) {
        List<Role> availableRoles = userService.getAllRoles();
        model.addAttribute("availableRoles", availableRoles);
        model.addAttribute("userList", userService.getAllUsersWithRoles());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserByEmail(username);
        model.addAttribute("userinfo", user);
        model.addAttribute("title", user.getFirstName() + " panel");
        model.addAttribute("user", new User());
        return "admin";
    }

    @PostMapping
    public String saveNewUser(Model model, @Valid User user, BindingResult result) {
        if (result.hasErrors()) {
            return "error";
        }
        String plainPassword = user.getPassword();
        String encodedPassword = passwordEncoder.encode(plainPassword);
        user.setPassword(encodedPassword);
        userService.saveUser(user);
        return "redirect:/admin";
    }


    @GetMapping("/editUser")
    public String displayEditUserForm(@RequestParam("id") Long id, Model model) {
        User user = userService.getUserById(id);
        List<Role> availableRoles = userService.getAllRoles();
        model.addAttribute("headerMessage", "Edit User Details");
        model.addAttribute("user", user);
        model.addAttribute("availableRoles", availableRoles);
        model.addAttribute("password", "");
        return "admin";
    }

    @PostMapping("/save-edited-user")
    public String saveEditedUser(@ModelAttribute("user") @Valid User user,
            @RequestParam("id") Long id,
            @RequestParam String password, BindingResult result) {

        if (result.hasErrors()) {
            return "error";
        }
        if (!password.isEmpty()) {
            user.setPassword(passwordEncoder.encode(password));
        }
        userService.saveUser(user);
        return "redirect:/admin";
    }

    @GetMapping("/delete-user")
    public String deleteUserById(@RequestParam("id") Long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }

    @GetMapping("/403")
    public String accessDenied() {
        return "403";
    }

}
