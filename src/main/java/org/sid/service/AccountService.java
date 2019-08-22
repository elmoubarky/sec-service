package org.sid.service;

import org.sid.entite.AppRole;
import org.sid.entite.AppUser;

public interface AccountService {
	
	public AppUser saveUser(String username, String password, String confirmed);
	public AppRole saveRole(AppRole appRole);
	public AppUser loadUserByUsername(String username);
	public void addRoleToUser(String username, String rolename);

}
