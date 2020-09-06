# JWT Authentication

# What is JWT?
JSON Web token (JWT) is an open standard that defines a compact and self-contained way for securely transmitting information between parties(from one end point to another end point) as a JSON object

# What is the JWT Structure?
In it's compact form, JWT consist of three parts separated by dots (.), which are:
 Format of JWT = header.payload.signature

# What is a Header in JWT?
The header typically consists of two parts
 1. The type of the token
    i. Which is basicallyJWT ("typ": "JWT")
 2. The Signing Algorthim
    i. HMAC SHA256 or RSA. ("alg": "HS256")
Header Signature will be
{
  "alg": "HS256",
  "typ": "JWT"
}
Then,this JSON header will be encoded into base64 (first part of the token).
example:
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

# PayLoad
The second part of the token is payload, which contains the claims.Claims are statements about an entity (typically, the user) and additional data
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
Then,this JSON payload will be encoded into base64.
Note: Do note that for signed tokens this information, though protected against tampering, is readable by anyone. Do not put secret information in the payload or header elements of a JWT unless it is encrypted.

# Signature
To create the signature part you have to take the encoded header + the encoded payload + a secret, with the algorithm specified in the header, and sign that.

HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
  
  The signature is used to verify the message wasn't changed along the way(between two parties or from one end to another points),
 
 # How to use JWT Authentication and Authorization in ASP.Net Core?
  The authentication with JWT tokens in ASP.NET Core is straightforward. Middleware exists in the Microsoft.AspNetCore.Authentication.JwtBearer package that does most of the work for us.
  Nuget Package Name: -
       Microsoft.AspNetCore.Authentication.JwtBearer
       
  In Startup.cs, ConfigureService method add,
  The AddAuthentication takes a AuthenticationOption parameter.it has 3 properties 
    1. DefaultAuthenticateScheme 
    2. DefaultChallengeScheme
    3. DefaultScheme. 
  These 3 are set to the default value of the AuthenticationScheme property in the JwtBearerAuthenticationOptions object, by the way this is "Bearer".
  
 
        services.AddAuthentication(options =>
      {
          options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
          options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
      })
      .AddJwtBearer(x =>
      {
          x.RequireHttpsMetadata = false;
          x.SaveToken = true;
          x.TokenValidationParameters = new TokenValidationParameters
          {
              ValidateIssuerSigningKey = true,
              IssuerSigningKey = new SymmetricSecurityKey(key),
              ValidateIssuer = false,
              ValidateAudience = false,
          };
      });
      
   Using AddJWTBearer extension method from the Microsoft.AspNetCore.Authentication.JwtBearer package,it takes a JwtBearerOptions parameter which specifies how to handle incoming tokens (Handler for authorizing the token).
   
  RequireHttpsMetadata is not used in the code snippet above, but is useful for testing purposes. In real-world deployments, JWT bearer tokens should always be passed only over HTTPS.
  
  TokenValidationParameters: -
  
     1. The ValidateIssuerSigningKey,ValidateAudience and ValdiateIssuer properties indicate that the token’s signature should be validated and that the key’s property indicating it’s issuer/Audience must match an expected value.
     
     2. The IssuerSigningKey is the secret key used for validating incoming JWT tokens
     
  
 In Configure Method add the authentication and authorization method,
  
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
         {
           //---- After the appuseRouting
             app.UseAuthentication();
             app.UseAuthorization();

           //----------------------------
         }
         
   Now Generate the token with help of MVC controller,
   
     {
              // authentication successful so generate jwt token
          var tokenHandler = new JwtSecurityTokenHandler();
          var key = Encoding.ASCII.GetBytes("SecretKey");
          var tokenDescriptor = new SecurityTokenDescriptor
          {
              Subject = new ClaimsIdentity(new Claim[]
              {
                  new Claim(ClaimTypes.Name, "Username"),
                  new Claim(ClaimTypes.Role, "Role")
              
              }),
              Expires = DateTime.UtcNow.AddDays(7),//Token Expiry date
              SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
          };
          var token = tokenHandler.CreateToken(tokenDescriptor);
          var jwtToken = tokenHandler.WriteToken(token);
       }
  
 
 Now decorate the some of actions/conroller(secure the API's) with [Authorize] attribute. Under the namespace of "Microsoft.AspNetCore.Authorization".
 
 To get Claims information from current identity: -
 
 var claims = User.Claims.ToList();
 
 To get current logged-in username from claims:-
 
 var username=User.Claims.FirstOrDefault(x=>x.Type==ClaimTypes.Name)
 
 
 
    
    
    
