package com.staynest.auth.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.staynest.auth.dto.request.LoginRequest;
import com.staynest.auth.dto.request.RefreshTokenRequest;
import com.staynest.auth.dto.request.RegisterRequest;
import com.staynest.auth.dto.response.AuthResponse;
import com.staynest.auth.dto.response.RegisterResponse;
import com.staynest.auth.service.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

	private final AuthService authService;

	@PostMapping("/register")
	public ResponseEntity<RegisterResponse> register(@Valid @RequestBody final RegisterRequest request) {
		final var response = authService.register(request);
		return ResponseEntity.status(HttpStatus.CREATED).body(response);
	}

	@PostMapping("/login")
	public ResponseEntity<AuthResponse> login(@Valid @RequestBody final LoginRequest request) {
		final var response = authService.login(request);
		return ResponseEntity.ok(response);
	}

	@PostMapping("/refresh-token")
	public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody final RefreshTokenRequest request) {
		final var response = authService.refreshToken(request);
		return ResponseEntity.ok(response);
	}

	@PostMapping("/logout")
	public ResponseEntity<Map<String, String>> logout(@Valid @RequestBody final RefreshTokenRequest request) {
		authService.logout(request);
		return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
	}
}

