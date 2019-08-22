package org.sid.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

/*
 * filtre permettant de verifier la veracite du token envoyer dans la requete pour l'utilisateur
 */
public class JWTAuthorizationFilter extends OncePerRequestFilter{

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		//ajout des fonctionnalites du CORS (Cross-Origin-Ressource-Sharing
		response.addHeader("Access-Control-Allow-Origin", "*"); //autoriser toutes les pages a envoyer requete
		response.addHeader("Access-Control-Allow-Headers", "Origin, Accept, X-Requested-With, "
				+ "Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, Authorization"); //entete autorise dans la requete
		response.addHeader("Access-Control-Expose-headers", "Acces-Control-Allow-Origin, "
				+ "Access-Control-Allow-Credential, authorization"); //entete expose pour un client HTTP il pourra lire les valeur
		
		//ajout des methodes autorises PUT DELETE etc....
		response.addHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH");
		
		
		/*
		 * quand une methode est envoye avec la methode OPTIONS pas besoin d'utiliser le token on repond avec "OK"
		 */
		if(request.getMethod().equals("OPTIONS")) {
			response.setStatus(HttpServletResponse.SC_OK);
		}
		/*
		 * exclure la methode de verification du token lors du login
		*/
		else if(request.getRequestURI().equals("/login")) {
			filterChain.doFilter(request, response);
			return;
		} 
		else {
		
		
		//recuperation du jwt
		String jwtToken = request.getHeader(SecurityParams.JWT_HEADER_NAME);
		//System.out.println("Token "+jwtToken);
		//test sur la valeur du jwt si egal a null ou commence pas par le prefix
		if(jwtToken==null || !jwtToken.startsWith(SecurityParams.HEADER_PREFIX)) {
			//appel du filtre suivant
			filterChain.doFilter(request, response);
			return ;
		}
		//verification de la signature du token
		JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build();
		
		//decodage du jwt en enlevant dabord le prefix
		String jwt = jwtToken.substring(SecurityParams.HEADER_PREFIX.length());
	//	System.out.println("JWT "+jwt);
		DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
		
		//recuperer le nom d'utilisateur, des roles dans le token
		String username = decodedJWT.getSubject();
		//System.out.println("Username "+username);
		
	     List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class);
	  //   System.out.println("Roles "+roles);
	     Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
	     roles.forEach(rn->{
	    	 authorities.add(new SimpleGrantedAuthority(rn));
	     });
	     
	     //definition d'un user de Spirng
	     UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(username, null, authorities);
	     
	     //indiquer a spring de faire l authentification de cet user
	     SecurityContextHolder.getContext().setAuthentication(user);
	   //appel du filtre suivant
			filterChain.doFilter(request, response);
	}
		
	}
}
