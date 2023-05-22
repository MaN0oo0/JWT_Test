using JWT_Test.Models;

namespace JWT_Test.Services
{
    public interface IAuthService
    {
        Task <AuthModel> RegisterAsync(RegisterModel model);
        Task <AuthModel> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
