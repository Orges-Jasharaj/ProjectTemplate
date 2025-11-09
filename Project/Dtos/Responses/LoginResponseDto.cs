namespace Project.Dtos.Responses
{
    public class LoginResponseDto
    {
        public string DisplayName { get; set; }
        public string Email { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
        public List<string> Roles { get; set; } = new();
    }
}
