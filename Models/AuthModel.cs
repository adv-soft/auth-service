namespace AuthService.Models;

public class AuthModel
{
    public int Id { get; set; }
    public string Password { get; set; }
    public string Email { get; set; }
    public string AccessToken { get; set; }
    public string Role { get; set; }
}