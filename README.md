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
       
  In Startup.cs, ConfigureService method add
        services.AddAuthentication(options =>
      {
          options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; //Bearer
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
   Using AddJWTBearer extension method,   
      

       
   
 
 


