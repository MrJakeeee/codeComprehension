package com.example.codecomprehension.auth;
import java.util.UUID;
public record UserView(UUID id, String email, String role) {}
