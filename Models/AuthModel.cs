using Newtonsoft.Json;
using System.Text.Json.Serialization;

namespace JWT_Test.Models
{
    public class AuthModel
    {
        public string Message { get; set; }
        public bool IsAuthenticated { get; set; }
        public string UserName { get; set; }

        public string Email { get; set; }
        public List<string> Roles { get; set; }
        public string Token { get; set; }
        //  public DateTime ExpireOn { get; set; }

        [System.Text.Json.Serialization.JsonIgnore]
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiration { get; set; }

        


    }
}
