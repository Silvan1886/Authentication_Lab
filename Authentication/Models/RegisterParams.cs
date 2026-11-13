using System.ComponentModel.DataAnnotations;

namespace Authentication.Models;

public class RegisterParams
{
    [Required]
    [StringLength(32, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 32 characters")]
    public string Username { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [StringLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}
