package com.staynest.auth.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.staynest.auth.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.expiration}")
	private long jwtExpirationMs;

	@Value("${jwt.refresh-expiration}")
	private long jwtRefreshExpirationMs;

	private SecretKey getSigningKey() {
		byte[] keyBytes;
		try {
			keyBytes = Decoders.BASE64.decode(secret);
			if (keyBytes.length < 32)
				keyBytes = MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
		} catch (final Exception e) {
			try {
				keyBytes = MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
			} catch (final NoSuchAlgorithmException ex) {
				keyBytes = secret.getBytes(StandardCharsets.UTF_8);
			}
		}
		return Keys.hmacShaKeyFor(keyBytes);
	}

	public String generateToken(final User user) {
		return Jwts.builder()
				.subject(user.getEmail())
				.claim("role", user.getRole() != null ? user.getRole().name() : null)
				.claim("tokenType", "ACCESS")
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
				.signWith(getSigningKey())
				.compact();
	}

	public String generateRefreshToken(final User user) {
		return Jwts.builder()
				.subject(user.getEmail())
				.claim("tokenType", "REFRESH")
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + jwtRefreshExpirationMs))
				.signWith(getSigningKey())
				.compact();
	}

	public String extractUsername(final String token) {
		return extractAllClaims(token).getSubject();
	}

	public String extractTokenType(final String token) {
		return extractAllClaims(token).get("tokenType", String.class);
	}

	public Date extractExpiration(final String token) {
		return extractAllClaims(token).getExpiration();
	}

	public boolean isTokenValid(final String token, final UserDetails userDetails) {
		try {
			final var username 		= extractUsername(token);
			final var tokenType 	= extractTokenType(token);

			return username != null && username.equalsIgnoreCase(userDetails.getUsername())
					&& !isTokenExpired(token)
					&& !"REFRESH".equalsIgnoreCase(tokenType);
		} catch (final Exception e) {
			return false;
		}
	}

	public boolean isRefreshTokenValid(final String token, final UserDetails userDetails) {
		try {
			final var username 	= extractUsername(token);
			final var tokenType = extractTokenType(token);
			return username != null && username.equalsIgnoreCase(userDetails.getUsername())
					&& !isTokenExpired(token)
					&& "REFRESH".equalsIgnoreCase(tokenType);
		} catch (final Exception e) {
			return false;
		}
	}

	private boolean isTokenExpired(final String token) {
		return extractAllClaims(token).getExpiration().before(new Date());
	}

	private Claims extractAllClaims(final String token) {
		return Jwts.parser()
				.verifyWith(getSigningKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

}
