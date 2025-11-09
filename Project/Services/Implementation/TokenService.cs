using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Project.Data.Models;
using Project.Dtos.Responses;
using Project.Dtos.System;
using Project.Services.Interface;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Project.Services.Implementation
{
    public class TokenService : ITokenService
    {

        private readonly JwtSettings _jwtSettings;

        public TokenService(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        public string GenerateAccessToken(User user, List<string> roles)
        {
            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey)),
                SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id),
        new Claim(ClaimTypes.Email, user.UserName),
        new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),

        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Iat,
                  new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
                  ClaimValueTypes.Integer64)
    };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var tokenOptions = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
                signingCredentials: signingCredentials);

            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }


        public RefreshTokenDto GenerateRrefreshToken()
        {
            var randomNumber = new byte[64];
            using (var numberGenerator = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                numberGenerator.GetBytes(randomNumber);
            }
            var expirationDate = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);

            var refreshTokenDto = new RefreshTokenDto
            {
                RefreshToken = Convert.ToBase64String(randomNumber),
                RefreshTokenExpiryDate = expirationDate
            };

            return refreshTokenDto;

        }

        public ClaimsPrincipal GetClaimsPrincipal(string token)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,

                IssuerSigningKey = securityKey,

            };
            return new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out _);
        }
    }
}
