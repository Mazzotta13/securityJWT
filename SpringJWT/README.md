README: GENERETE AND VALIDATE JWT TOKEN
Esempio da: 
https://medium.com/swlh/spring-boot-security-jwt-hello-world-example-b479e457664c
Progetto Git:
https://github.com/Mazzotta13/securityJWT
- Creremo prima un controller a cui accedere tramite chiamata REST. 
- Dovremo quindi fare in modo di generare il token JWT esponendo un'API POST a /authenticate. Passando i giusti username e password genereremo il token jWT.
- Se un utente prova ad accedere all'API /hello verrà consentito l'accesso solo se la richiesta ha comprende un token valido.

GENERARE UN TOKEN
1) Chiamata POST ad /authenticate con username e password.
2) controllare se la richiesta comprende un token
3) se la richiesta non comprende un token generare un token con il metodo genereteAuthenticationToken()
4) validare username e password con il metodo authenticate()
5) caricare userDetail usando l'username dal DB
6) ritornare Username con username e password
7) se l'utente è valido ritornare true altrimenti lanciare eccezione InvalidUserException
8) se l'utente è valido generare un token con generateToken(UserDetail)
9) Ritornare il token

VALIDARE JWT
1) chiamata /hello con JWT Token in Header
2) controllare che la richiesta ha il token. Se è presente estrarre il token
3) Caricare UserDetail usando lo username
4) ritorna UserDetail
5) valida il JWT Token (metodo validateToken(JwtToken))
6) Ritorna true se il token è valido
7) se il token è valido configurare il contesto di sicurezza per l'utente
8) chiama il metodo helloWorld

PROGETTO
0) Dipendenze:
- Spring boot starter security, Spring Boot starter web
- JWT Dependency:
<dependency>
	<groupId>io.jsonwebtoken</groupId>
	<artifactId>jjwt</artifactId>
	<version>0.9.1</version>
</dependency>

1) Creare controller:
@RestController
public class HelloWorldController {
	
	@GetMapping({"/","/",""})
	public String helloWorld() {
		return "Hello World";
	}
}

2) definire la secret per effettuare l'hash del token:
jwt.secret=javainuse

3) JwtTokenUtils (per generare e validare i token)
- Generete token:
public String generateToken(UserDetails userDetails) {
	Map<String, Object> claims = new HashMap<>();
	return doGenerateToken(claims, userDetails.getUsername());
}

private String doGenerateToken(Map<String, Object> claims, String subject) {
	return Jwts.builder()
		.setClaims(claims)
		.setSubject(subject)
		.setIssuedAt(new Date(System.currentTimeMillis()))
		.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
		.signWith(SignatureAlgorithm.HS512, secret).compact();
}

- Validate Token:
public Boolean validateToken(String token, UserDetails userDetails) {
	final String username = getUsernameFromToken(token);
	return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
}

//retrieve username from jwt token
public String getUsernameFromToken(String token) {
	return getClaimFromToken(token, Claims::getSubject);
}
//retrieve expiration date from jwt token
public Date getExpirationDateFromToken(String token) {
	return getClaimFromToken(token, Claims::getExpiration);
}
public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
	final Claims claims = getAllClaimsFromToken(token);
	return claimsResolver.apply(claims);
}
//for retrieveing any information from token we will need the secret key
private Claims getAllClaimsFromToken(String token) {
	return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
}
//check if the token has expired
private Boolean isTokenExpired(String token) {
	final Date expiration = getExpirationDateFromToken(token);
	return expiration.before(new Date());
}

NOTA: getClaimFromToken(String token, Function<Claims, T> claimsResolver): ha come secondo argomento una funzione che rappresenta come i dati vengono recuperati (ad esempio subjecet e expiration)

4) JwtUserDetailService
Implementa UserDetailsService e sovrascrivendo il metodo loadUserByUsername indica come recuperare i dati utente. 
NOTA: in questo momento solo un utente risulterà valido dovremo poi fare in modo di poter effettuare registrazioni e recupero dati da un DB.
@Service
public class JwtUserDetailsService implements UserDetailsService {
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if ("javainuse".equals(username)) {
			return new User("javainuse", "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6",
					new ArrayList<>());
		} else {
			throw new UsernameNotFoundException("User not found with username: " + username);
		}
	}
}

5) JwtAuthenticationController
In questa classe ci sarà la URL (/authenticate) per creare un token. 
@RestController
@CrossOrigin
public class JwtAuthenticationController {
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Autowired
	private JwtUserDetailsService userDetailsService;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {
		authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
		final UserDetails userDetails = userDetailsService
				.loadUserByUsername(authenticationRequest.getUsername());
		final String token = jwtTokenUtil.generateToken(userDetails);
		return ResponseEntity.ok(new JwtResponse(token));
	}

	private void authenticate(String username, String password) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception("USER_DISABLED", e);
		} catch (BadCredentialsException e) {
			throw new Exception("INVALID_CREDENTIALS", e);
		}
	}
}

6) 2 models JwtRequest and jwtResponse
... semplici vedi codice

7) JwtRequestFilter
@Component
public class JwtRequestFilter extends OncePerRequestFilter {
	@Autowired
	private JwtUserDetailsService jwtUserDetailsService;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		final String requestTokenHeader = request.getHeader("Authorization");
		String username = null;
		String jwtToken = null;
		// JWT Token is in the form "Bearer token". Remove Bearer word and get
		// only the Token
		if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
			jwtToken = requestTokenHeader.substring(7);
			try {
				username = jwtTokenUtil.getUsernameFromToken(jwtToken);
			} catch (IllegalArgumentException e) {
				System.out.println("Unable to get JWT Token");
			} catch (ExpiredJwtException e) {
				System.out.println("JWT Token has expired");
			}
		} else {
			logger.warn("JWT Token does not begin with Bearer String");
		}
		// Once we get the token validate it.
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
			// if token is valid configure Spring Security to manually set
			// authentication
			if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// After setting the Authentication in the context, we specify
				// that the current user is authenticated. So it passes the
				// Spring Security Configurations successfully.
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		chain.doFilter(request, response);
	}
}

8) WebSecurityConfig:
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
	@Autowired
	private UserDetailsService jwtUserDetailsService;
	@Autowired
	private JwtRequestFilter jwtRequestFilter;
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		// configure AuthenticationManager so that it knows from where to load
		// user for matching credentials
		// Use BCryptPasswordEncoder
		auth.userDetailsService(jwtUserDetailsService).passwordEncoder(passwordEncoder());
	}
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		// We don't need CSRF for this example
		httpSecurity.csrf().disable()
				// dont authenticate this particular request
				.authorizeRequests().antMatchers("/authenticate").permitAll().
				// all other requests need to be authenticated
				anyRequest().authenticated().and().
				// make sure we use stateless session; session won't be used to
				// store user's state.
				exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint).and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		// Add a filter to validate the tokens with every request
		httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
	}
}

TEST
1) Ottenere token: Su Postman effettuare call POST a localhost:8080/authenticate.
- body:
{
	"username": "javainuse",
	"password": "password"
}
2) accedere a localhost:8080/hello validando il token:
Su postman call GET a localhost:8080/hello.
- in header: Authorization Bearer TOKEN_RICEVUTO_PASSO_1