namespace MyApi.Models.Users;

public sealed class UpdateUserRequest
{
    [JsonPropertyName("fullName")]
    [Required(ErrorMessage = "Full name is required.")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "Full name must be between 2 and 100 characters.")]
    public string FullName { get; set; } = string.Empty;


    [JsonPropertyName("phoneNumber")]
    [Required(ErrorMessage = "Phone number is required.")]
    [Phone(ErrorMessage = "Please enter a valid phone number.")]
    public string PhoneNumber { get; set; } = string.Empty;
}