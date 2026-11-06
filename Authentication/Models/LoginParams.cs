using System.ComponentModel.DataAnnotations;

namespace Authentication.Models;

public class LoginParams
{
    [Required]
    [StringLength(32, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 32 characters")]
    public string Username { get; set; }
    [Required]
    public string Password { get; set; }
}