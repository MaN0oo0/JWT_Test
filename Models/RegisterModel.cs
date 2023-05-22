using Microsoft.Build.Framework;
using System.ComponentModel.DataAnnotations;

namespace JWT_Test.Models
{
    public class RegisterModel
    {
        [ StringLength(50)]
        public string FirstName { get; set; }
        [ StringLength(50)]
        public string LastName { get; set; }
        [ StringLength(50)]
        public string Email { get; set; }
        [ StringLength(256)]
        public string Password { get; set; }
        [ StringLength(50)]
        public string UserName { get; set; }
    }
}
