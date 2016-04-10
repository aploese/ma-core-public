/**
 * Copyright (C) 2015 Infinite Automation Software. All rights reserved.
 * @author Terry Packer
 */
package com.serotonin.m2m2.web.mvc.spring.authentication;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.serotonin.m2m2.db.dao.UserDao;
import com.serotonin.m2m2.vo.User;

/**
 * Class for plug-in User Access for Authentication Data
 * 
 * @author Terry Packer
 *
 */
public class MangoUserDetailsService implements UserDetailsService {

	/* (non-Javadoc)
	 * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		
		User u = UserDao.instance.getUser(username);
		if(u != null)
			return new MangoUser(u, getGrantedAuthorities(u));
		
		throw new UsernameNotFoundException(username);
	}
	
	public static Set<GrantedAuthority> getGrantedAuthorities(User user) {
	    String[] roles = user.getPermissions().split(",");
        Set<GrantedAuthority> permissions = new HashSet<GrantedAuthority>(roles.length);

        for (String role : roles) {
            permissions.add(new SimpleGrantedAuthority("ROLE_" + role.trim().toUpperCase()));
        }

        permissions.add(new SimpleGrantedAuthority("ROLE_USER"));
        if (user.isAdmin())
            permissions.add(new SimpleGrantedAuthority("ROLE_SUPERADMIN"));
        
        return permissions;
	}
}
