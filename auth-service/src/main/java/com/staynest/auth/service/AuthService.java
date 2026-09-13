package com.staynest.auth.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.staynest.auth.dto.request.LoginRequest;
import com.staynest.auth.dto.request.RefreshTokenRequest;
import com.staynest.auth.dto.request.RegisterRequest;
import com.staynest.auth.dto.response.AuthResponse;
import com.staynest.auth.dto.response.RegisterResponse;

public interface AuthService extends UserDetailsService {

	RegisterResponse register(RegisterRequest request);

	AuthResponse login(LoginRequest request);

	AuthResponse  refreshToken(RefreshTokenRequest request);
	
	void logout(RefreshTokenRequest request);
}
