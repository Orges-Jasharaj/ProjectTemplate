using Project.Data.Models;
using Project.Dtos.Responses;
using System.Security.Claims;

namespace Project.Services.Interface
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user, List<string> roles);
        RefreshTokenDto GenerateRrefreshToken();

        ClaimsPrincipal GetClaimsPrincipal(string token);
    }
}
