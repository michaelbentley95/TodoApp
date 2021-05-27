using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TodoApp.Configuration;
using TodoApp.Data;
using TodoApp.Models;
using TodoApp.Models.DTOs.Requests;
using TodoApp.Models.DTOs.Responses;

namespace TodoApp.Controllers
{
    [Route("api/[controller]")] //api/authManagement
    [ApiController]
    public class AuthManagementController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        private readonly TokenValidationParameters _tokenValidationParams;
        private readonly ApiDbContext _apiDbContext;

        public AuthManagementController(UserManager<IdentityUser> userManager, IOptionsMonitor<JwtConfig> optionsMonitor, TokenValidationParameters tokenValidationParams, ApiDbContext apiDbContext)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _tokenValidationParams = tokenValidationParams;
            _apiDbContext = apiDbContext;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDTO user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);
                if (existingUser != null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Email Already in Use"
                        }
                    });
                }
                var newUser = new IdentityUser() { Email = user.Email, UserName = user.Username };
                var isCreated = await _userManager.CreateAsync(newUser, user.Password);
                if (isCreated.Succeeded)
                {
                    var jwtToken = await GenerateJwtToken(newUser);
                    return Ok(jwtToken);
                }
                else
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Success = false,
                        Errors = isCreated.Errors.Select(x => x.Description).ToList()
                    });
                }
            }
            return BadRequest(new RegistrationResponse()
            {
                Success = false,
                Errors = new List<string>() {
                    "Invalid Payload"
                }
            });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDTO user)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);
                if (existingUser == null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Invalid login"
                        }
                    });
                }
                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);
                if (!isCorrect)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Invalid login"
                        }
                    });
                }

                var jwtToken = await GenerateJwtToken(existingUser);

                return Ok(jwtToken);
            }
            return BadRequest(new RegistrationResponse()
            {
                Success = false,
                Errors = new List<string>() {
                    "Invalid Payload"
                }
            });
        }

        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = await VerifyandGenerateToken(tokenRequest);

                if (result == null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Invalid tokens"
                        }
                    });

                    return Ok(result);
                }

                return Ok(result);
            }
            return BadRequest(new RegistrationResponse()
            {
                Success = false,
                Errors = new List<string>() {
                    "Invalid Payload"
                }
            });
        }

        private async Task<AuthResult> VerifyandGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                //Validation 1: Valid JWT token format
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParams, out var validatedToken);

                //Validation 2: Valid Encryption Algorithm
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (result == false)
                    {
                        return null;
                    }
                }

                //Validation 3: Validate Expiration
                var utcExpirationDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
                var expirationDate = UnixTimeStampToDateTime(utcExpirationDate);
                if (expirationDate > DateTime.UtcNow)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "No need to refresh. Token hasn't expired"
                        }
                    };
                }

                //Validation 4: Refresh token exists in the database
                var storedToken = await _apiDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedToken == null)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Token does not exist"
                        }
                    };
                }

                //Validation 5: Refresh Token hasn't already been used
                if (storedToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Stored Token has been used"
                        }
                    };
                }

                //Validation 6: Refresh Token hasn't been revoked
                if (storedToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Stored Token has been revoked"
                        }
                    };
                }

                //Validation 7: The Guid of the Json Token ID in the DB matches what was passed in
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
                if (storedToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>() {
                            "Token does not match"
                        }
                    };
                }

                //Update refresh token in db
                storedToken.IsUsed = true;
                _apiDbContext.RefreshTokens.Update(storedToken);
                await _apiDbContext.SaveChangesAsync();

                //Generate new token
                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtToken(dbUser);
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimeVal;
        }

        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]{
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, System.Guid.NewGuid().ToString()),
                }),
                Expires = DateTime.UtcNow.AddSeconds(30), //ToDo Change to 5-10 minutes
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                UserId = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpirationDate = DateTime.UtcNow.AddMonths(6),
                Token = RandomString(35) + Guid.NewGuid()
            };

            await _apiDbContext.RefreshTokens.AddAsync(refreshToken);
            await _apiDbContext.SaveChangesAsync();

            return new AuthResult()
            {
                Token = jwtToken,
                Success = true,
                RefreshToken = refreshToken.Token
            };
        }

        private string RandomString(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}