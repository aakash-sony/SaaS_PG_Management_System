package com.staynest.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.staynest.auth.entity.User;
import com.staynest.auth.enums.Role;
import com.staynest.auth.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@Order(1)
@RequiredArgsConstructor
public class SuperAdminDataSeeder implements CommandLineRunner {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@Value("${superadmin.username}")
	private String adminEmail;

	@Value("${superadmin.password}")
	private String adminPassword;

	@Override
	@Transactional
	public void run(final String... args) {
		if (!StringUtils.hasText(adminEmail) || !StringUtils.hasText(adminPassword)) {
			log.warn("Super admin credentials are not configured. Skipping super admin data seeding.");
			return;
		}

		if (userRepository.existsByRole(Role.SUPER_ADMIN)) {
			log.info("Super Admin already exists. Skipping initialization.");
			return;
		}

		if (userRepository.existsByEmail(adminEmail)) {
			log.warn("User with email '{}' already exists with a different role. Skipping Super Admin seeding to prevent duplicate email conflict.", adminEmail);
			return;
		}

		final var superAdmin = User.builder()
				.fullName("Super Admin")
				.email(adminEmail.trim().toLowerCase())
				.password(passwordEncoder.encode(adminPassword))
				.role(Role.SUPER_ADMIN)
				.isActive(true)
				.build();

		userRepository.save(superAdmin);
		log.info("Super Admin account seeded successfully with email: {}", adminEmail);
	}
}

