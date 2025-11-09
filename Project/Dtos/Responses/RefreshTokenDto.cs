namespace Project.Dtos.Responses
{
    public class RefreshTokenDto
    {
        public string RefreshToken { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
        public DateTime RefreshTokenExpiryDate { get; set; }
    }
}
