using System.ComponentModel.DataAnnotations;

namespace Authentication.Models;

public class ChangeUsernameParams
{
    [Required]
    [StringLength(32, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 32 characters")]
    public string Username { get; set; } = string.Empty;
}
