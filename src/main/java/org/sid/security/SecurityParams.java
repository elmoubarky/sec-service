package org.sid.security;

//interface de definition des constances de l'application
public interface SecurityParams {
	
	public static final String JWT_HEADER_NAME = "Authorization";
	public static final String SECRET = "med@youssfi.net";
	public static final long EXPIRATION = 10*24*3600*1000;
	public static final String HEADER_PREFIX = "Bearer ";

}
