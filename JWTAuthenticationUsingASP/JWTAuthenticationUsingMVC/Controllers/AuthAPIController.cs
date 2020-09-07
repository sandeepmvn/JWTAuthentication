using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWTAuthenticationUsingMVC.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthenticationUsingMVC.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthAPIController : ControllerBase
    {
        [HttpPost("Authenticate")]
        public IActionResult Authenticate([FromBody] AuthModel authModel)//model binder
        {
            if (string.IsNullOrEmpty(authModel.UserName) || string.IsNullOrEmpty(authModel.password))
                return Unauthorized();

            if (authModel.UserName == authModel.password)
            {
                //authentication is success
                var tokenHandler = new JwtSecurityTokenHandler();
                //tokenHandler.CreateToken()
                var key = Encoding.ASCII.GetBytes("Security@123456789");
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
              new Claim(ClaimTypes.Name, authModel.UserName),
              new Claim(ClaimTypes.Role, "Admin")

                    }),
                    Expires = DateTime.UtcNow.AddDays(7),//Token Expiry date
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var jwtToken = tokenHandler.WriteToken(token);
                return Ok(jwtToken);
            }
            return Unauthorized();
        }
        
        [Authorize]
        public IActionResult GetAllUsers()
        {

          var claims=User.Claims.ToList();
            User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);
            return Ok(new List<string>() { "Schott1", "Schott2", "admin" });
        }




    }
}
