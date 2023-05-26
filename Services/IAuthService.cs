using JWT_Test.Models;

namespace JWT_Test.Services
{
    public interface IAuthService
    {
        Task <AuthModel> RegisterAsync(RegisterModel model);
        Task <AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
        Task<AuthModel> RefreshTokenAsync(string Token);
        Task<bool> RevokTokenAsync(string Token);
    }
}
