package org.sid.service;

import javax.transaction.Transactional;

import org.sid.dao.AppRoleRepository;
import org.sid.dao.AppUserRepository;
import org.sid.entite.AppRole;
import org.sid.entite.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class AccountServiceImpl implements AccountService{

	//@Autowired
	private AppRoleRepository appRoleRepository;
	
	//@Autowired
	private AppUserRepository appUserRepository;
	
	//crypter le mot de passe avec Bcrypt
	//@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	
	
	public AccountServiceImpl(AppRoleRepository appRoleRepository, AppUserRepository appUserRepository,
			BCryptPasswordEncoder bCryptPasswordEncoder) {
		super();
		this.appRoleRepository = appRoleRepository;
		this.appUserRepository = appUserRepository;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}

	@Override
	public AppUser saveUser(String username, String password, String confirmed) {
		// TODO Auto-generated method stub
		
		AppUser user = appUserRepository.findByUsername(username);
		//verifier si l'utilisateur n'existe pas
		if(user!=null)throw new RuntimeException("User already exists");
		//verifier la conformite des deux password
		if(!password.equals(confirmed))throw new RuntimeException("please confirme your password");
		//creation de l'user
		AppUser appUser = new AppUser();
		appUser.setUsername(username);
		appUser.setPassword(bCryptPasswordEncoder.encode(password));
		appUser.setActived(true);
		appUserRepository.save(appUser);
		
		//ajouter un role a un utilisateur
		addRoleToUser(username, "USER");
		
		
		return appUser;
	}

	@Override
	public AppRole saveRole(AppRole appRole) {
		// TODO Auto-generated method stub
		return appRoleRepository.save(appRole);
	}

	@Override
	public AppUser loadUserByUsername(String username) {
		// TODO Auto-generated method stub
		return appUserRepository.findByUsername(username);
	}

	@Override
	public void addRoleToUser(String username, String rolename) {
		// TODO Auto-generated method stub
		AppUser user = appUserRepository.findByUsername(username);
		AppRole role = appRoleRepository.findByRoleName(rolename);
		user.getRoles().add(role);
		
	}

}
