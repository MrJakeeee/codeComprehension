package com.example.codecomprehension.admin;
import com.example.codecomprehension.auth.UserView;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
@RestController
@RequestMapping("/api/admin")
public class AdminController {
 @GetMapping("/me") public UserView me(@AuthenticationPrincipal UserView user){return user;}
}
