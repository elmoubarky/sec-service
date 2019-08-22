package org.sid.security;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sid.entite.AppUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JWTAuthentificationFilter extends UsernamePasswordAuthenticationFilter {
	
	private AuthenticationManager authenticationManager;

	public JWTAuthentificationFilter(AuthenticationManager authenticationManager) {
		super();
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		 
		//recuperation des donnes username et pass en format json
		try {
			AppUser appUser = new ObjectMapper().readValue(request.getInputStream(), AppUser.class);
			return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(appUser.getUsername(), appUser.getPassword()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException("Problem in request content" +e);
		}
		
		
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		//generation du token JWT
		User user = (User) authResult.getPrincipal();
		List<String> roles = new ArrayList<>();
		authResult.getAuthorities().forEach(a->{		
			roles.add(a.getAuthority());
		});
		
		//creation du JWT
		String jwt = JWT.create()
				.withIssuer(request.getRequestURI()) //recuperation d el'url
				.withSubject(user.getUsername())  //le nom d 'utilisateur
				.withArrayClaim("roles", roles.toArray(new String[roles.size()]))  //tableau de strig pour les roles
				.withExpiresAt(new Date(System.currentTimeMillis()+SecurityParams.EXPIRATION)) //date d expiration date systeme x 10jours
				.sign(Algorithm.HMAC256(SecurityParams.SECRET)); //signer les token car le jwt a 3 parties : header playload et token
		
		//ajouter le jwt dans le header
		response.addHeader(SecurityParams.JWT_HEADER_NAME, jwt);
		
		
	}

}
