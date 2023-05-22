using JWT_Test.Helpers;
using JWT_Test.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Test.Services
{

    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly Jwt _jwt;
        public AuthService(UserManager<ApplicationUser> userManager, IOptions<Jwt> jwt, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _roleManager = roleManager;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {

            if (await _userManager.FindByEmailAsync(model.Email) !=null)
            {
                return new AuthModel { Message = "Email Is Already Registered" };
            }
            if (await _userManager.FindByNameAsync(model.UserName) is not null)
            {
                return new AuthModel { Message = "UserName Is Already Registered" };
            }
            else
            {

                var data = new ApplicationUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    LastName = model.LastName,
                    FirstName = model.FirstName,

                };
                var result = await _userManager.CreateAsync(data, model.Password);
                if (!result.Succeeded)
                {
                    string Error = string.Empty;
                    foreach (var item in result.Errors)
                    {
                        Error += $"{item.Description}";
                    }
                    return new AuthModel { Message = Error };
                }


                await _userManager.AddToRoleAsync(data, "User");
                dynamic jwtSecurityToken ;
                try
                {
                     jwtSecurityToken = await CreateJwtToken(data);
                }
                catch (Exception ex)
                {

                    throw ex;
                }
                return new AuthModel
                {
                    Email=data.Email,
                    ExpireOn=jwtSecurityToken.ValidTo,
                    IsAuthenticated=true,
                    Roles=new List<string> { "User"},
                    UserName=data.UserName,
                    Token=new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
                };
            }
        }
        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var AuthModel = new AuthModel();

            var User = await _userManager.FindByEmailAsync(model.Email);
            var RoleList = await _userManager.GetRolesAsync(User);
          
            if (User is null || !await _userManager.CheckPasswordAsync(User, model.Password)) 
            {
                AuthModel.Message = "Email Or Password Is InCorrect";
                return AuthModel;
            }
         
            var jwtSecurityToken = await CreateJwtToken(User);
           
            AuthModel.IsAuthenticated= true;
            AuthModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            AuthModel.UserName = User.UserName;
            AuthModel.ExpireOn=jwtSecurityToken.ValidTo;
            AuthModel.Email = User.Email;
            AuthModel.Roles = RoleList.ToList();

            return AuthModel;
            }
        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";

            if (await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            return result.Succeeded ? string.Empty : "Sonething went wrong";
        }
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
