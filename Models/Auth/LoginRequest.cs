namespace MyApi.Models.Auth;


public sealed class LoginRequest
{
    [JsonPropertyName("email")]
    [Required(ErrorMessage = "Email address is required.")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
    public string Email { get; set; } = string.Empty;


    [JsonPropertyName("password")]
    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}
