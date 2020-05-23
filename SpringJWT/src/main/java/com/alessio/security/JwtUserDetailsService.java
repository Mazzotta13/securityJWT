package com.alessio.security;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.alessio.security.model.UserSecurity;
import com.alessio.security.repository.UserDetailRepository;

@Service
public class JwtUserDetailsService implements UserDetailsService {
	private UserDetailRepository userDetailRepository;
	
	public JwtUserDetailsService(UserDetailRepository userDetailRepository) {
		this.userDetailRepository = userDetailRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserSecurity user = userDetailRepository.findByUsername(username);
		if (user != null) {
			return new User(user.getUsername(), user.getPassword(), user.getAuthorities());
		}  else throw new UsernameNotFoundException("User not found with username: " + username);
//		if ("javainuse".equals(username)) {
//			return new User("javainuse", "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6",
//					new ArrayList<>());
//		} else {
//			throw new UsernameNotFoundException("User not found with username: " + username);
//		}
	}
}