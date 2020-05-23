package com.alessio.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.alessio.security.model.UserSecurity;

public interface UserDetailRepository extends JpaRepository<UserSecurity, Long>{
	UserSecurity findByUsername(String username);
}
