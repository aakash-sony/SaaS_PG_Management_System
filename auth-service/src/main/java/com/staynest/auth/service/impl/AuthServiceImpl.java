package com.staynest.auth.service.impl;

import java.time.Instant;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.staynest.auth.dto.request.LoginRequest;
import com.staynest.auth.dto.request.RefreshTokenRequest;
import com.staynest.auth.dto.request.RegisterRequest;
import com.staynest.auth.dto.response.AuthResponse;
import com.staynest.auth.dto.response.RegisterResponse;
import com.staynest.auth.entity.RefreshToken;
import com.staynest.auth.entity.User;
import com.staynest.auth.enums.Role;
import com.staynest.auth.exception.UserAlreadyExistsException;
import com.staynest.auth.repository.RefreshTokenRepository;
import com.staynest.auth.repository.UserRepository;
import com.staynest.auth.security.JwtService;
import com.staynest.auth.service.AuthService;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

	private final UserRepository 			userRepository;
	private final RefreshTokenRepository 	refreshTokenRepository;
	private final PasswordEncoder 			passwordEncoder;
	private final JwtService 				jwtService;

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {

		return userRepository.findByEmail(email.trim().toLowerCase())
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
	}

	@Override
	public RegisterResponse register(final RegisterRequest request) {
		if (request.getPassword() == null || !request.getPassword().equals(request.getConfirmPassword()))
			throw new IllegalArgumentException("Passwords do not match");

		final var normalizedEmail = request.getEmail().trim().toLowerCase();

		if (userRepository.existsByEmail(normalizedEmail))
			throw new UserAlreadyExistsException("User with email '" + normalizedEmail + "' already exists");

		String mobileNumber 	= null;

		if (request.getMobileNumber() != null && !request.getMobileNumber().isBlank()) {

			mobileNumber 		= request.getMobileNumber().trim();

			if (userRepository.existsByMobileNumber(mobileNumber))
				throw new UserAlreadyExistsException("User with mobile number '" + mobileNumber + "' already exists");
		}

		if (request.getRole() == Role.SUPER_ADMIN)
			throw new IllegalArgumentException("Registration with SUPER_ADMIN role is not permitted");

		final var assignedRole 	= request.getRole() != null ? request.getRole() : Role.RESIDENT;

		final var user 			= User.builder()
				.fullName(request.getFullName().trim())
				.email(normalizedEmail)
				.password(passwordEncoder.encode(request.getPassword()))
				.mobileNumber(mobileNumber)
				.role(assignedRole)
				.isActive(true)
				.build();

		userRepository.save(user);

		return new RegisterResponse("User registered successfully");
	}

	@Override
	public AuthResponse login(final LoginRequest request) {
		final var normalizedEmail = request.getEmail().trim().toLowerCase();

		final var user = userRepository.findByEmail(normalizedEmail)
				.orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword()))
			throw new BadCredentialsException("Invalid email or password");

		if (Boolean.FALSE.equals(user.getIsActive()))
			throw new DisabledException("User account is inactive. Please contact administration.");

		final var accessToken 		= jwtService.generateToken(user);
		final var refreshToken 		= jwtService.generateRefreshToken(user);

		refreshTokenRepository.save(createRefreshToken(refreshToken, user));

		return buildAuthResponse(user, accessToken, refreshToken);
	}

	@Override
	public AuthResponse refreshToken(final RefreshTokenRequest request) {
		final var storedToken 	= validateAndGetRefreshToken(request.getRefreshToken());

		final var user 			= storedToken.getUser();

		if (Boolean.FALSE.equals(user.getIsActive()))
			throw new DisabledException("User account is inactive. Please contact administration.");

		final var newAccessToken 		= jwtService.generateToken(user);
		final var newRefreshToken 		= jwtService.generateRefreshToken(user);

		// Revoke old refresh token
		storedToken.setRevoked(true);

		// Store new refresh token
		refreshTokenRepository.save(createRefreshToken(newRefreshToken, user));

		return buildAuthResponse(user, newAccessToken, newRefreshToken);
	}

	@Override
	public void logout(final RefreshTokenRequest request) {
		final var storedToken = validateAndGetRefreshToken(request.getRefreshToken());

		storedToken.setRevoked(true);
	}

	/**
	 * Validates the refresh token against both JWT and database.
	 */
	private RefreshToken validateAndGetRefreshToken(final String refreshToken) {

		if (refreshToken == null || refreshToken.isBlank())
			throw new BadCredentialsException("Refresh token cannot be blank");

		final String email;

		try {
			email = jwtService.extractUsername(refreshToken);
		} catch (final Exception e) {
			throw new BadCredentialsException("Invalid or expired refresh token");
		}

		if (email == null)
			throw new BadCredentialsException("Invalid refresh token");

		final var user = userRepository.findByEmail(email.trim().toLowerCase())
				.orElseThrow(() -> new BadCredentialsException("User not found"));

		if (!jwtService.isRefreshTokenValid(refreshToken, user))
			throw new BadCredentialsException("Invalid or expired refresh token");

		final var storedToken = refreshTokenRepository.findByToken(refreshToken)
				.orElseThrow(() -> new BadCredentialsException("Refresh token not found"));

		if (!storedToken.getUser().getId().equals(user.getId()))
			throw new BadCredentialsException("Invalid refresh token");

		if (Boolean.TRUE.equals(storedToken.getRevoked()))
			throw new BadCredentialsException("Refresh token has been revoked");

		if (storedToken.getExpiryDate().isBefore(Instant.now()))
			throw new BadCredentialsException("Refresh token has expired");

		return storedToken;
	}


	private RefreshToken createRefreshToken(final String token, final User user) {
		return RefreshToken.builder()
				.token(token)
				.user(user)
				.expiryDate(jwtService.extractExpiration(token).toInstant())
				.revoked(false)
				.build();
	}

	private AuthResponse buildAuthResponse(final User user, final String accessToken, final String refreshToken) {
		return AuthResponse.builder()
				.accessToken(accessToken)
				.refreshToken(refreshToken)
				.tokenType("Bearer")
				.userId(user.getId())
				.fullName(user.getFullName())
				.email(user.getEmail())
				.role(user.getRole().name())
				.build();
	}
}