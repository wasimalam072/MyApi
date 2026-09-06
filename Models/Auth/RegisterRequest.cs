namespace MyApi.Models.Auth;

public sealed class RegisterRequest
{
    [JsonPropertyName("fullName")]
    [Required(ErrorMessage = "Full name is required.")]
    [StringLength(
        100,
        MinimumLength = 2,
        ErrorMessage = "Full name must be between 2 and 100 characters.")]
    public string FullName { get; set; } = string.Empty;


    [JsonPropertyName("email")]
    [Required(ErrorMessage = "Email address is required.")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address.")]
    public string Email { get; set; } = string.Empty;


    [JsonPropertyName("phoneNumber")]
    [Required(ErrorMessage = "Phone number is required.")]
    [Phone(ErrorMessage = "Please enter a valid phone number.")]
    public string PhoneNumber { get; set; } = string.Empty;


    [JsonPropertyName("password")]
    [Required(ErrorMessage = "Password is required.")]
    [MinLength(
        8,
        ErrorMessage = "Password must contain at least 8 characters.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;


    [JsonPropertyName("confirmPassword")]
    [Required(ErrorMessage = "Please confirm your password.")]
    [Compare(
        nameof(Password),
        ErrorMessage = "Password and confirmation password do not match.")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; } = string.Empty;
}