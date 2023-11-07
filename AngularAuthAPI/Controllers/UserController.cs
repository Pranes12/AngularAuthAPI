using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]

        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);
            if (user == null)
                return NotFound(new { Message = "User Nor Found!" });

            if (!PasswordHasher.VerifyPassword(userObj.Password,user.Password))
                return BadRequest(new
                {
                    Message ="Password Is InCorrect"
                });

            user.Token = CreateJwt(user);

            return Ok(new
            {
                Token = user.Token,
                Message = "Login Success!"
            });
        }

        [HttpPost("register")]

        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            //Check UserName

            if (await CheckUserNameExistAsync(userObj.UserName))
                return BadRequest(new
                {
                    Message = "UserName Already Exist!"
                });

            //Check Email

            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new
                {
                    Message = "Email Already Exist!"
                });


            //Check Password Strength
            var pass = CheckPasswordStrength (userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new
                {
                    Message = pass.ToString()
                });



            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new {
                Message = "User Registered!"
            });
        }

        private Task<bool> CheckUserNameExistAsync(string userName)
        
            => _authContext.Users.AnyAsync(x => x.UserName == userName);

        private Task<bool> CheckEmailExistAsync(string email)

          => _authContext.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
                sb.Append("Minimum Password length should be 8" + Environment.NewLine);
            if(!(Regex.IsMatch(password,"[a-z]") &&  Regex.IsMatch(password,"[A-Z]")
                && Regex.IsMatch(password,"[0-9]")))
                sb.Append("Need AlphaNumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',.,~,`,]"))
                sb.Append("Password Should Contain Special Character");
            return sb.ToString();
        }

        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("very verysecret.....");
            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name,$"{user.FirstName}:{user.LastName}"),
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GettAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
    }
}
