using Project.Dtos.Requests;
using Project.Dtos.Responses;
using System.Security.Claims;

namespace Project.Services.Interface
{
    public interface IUser
    {
        Task<ResponseDto<bool>> CreateUserAsync(CreateUserDto createUserDto);
        Task<ResponseDto<bool>> CreateUserWithRoleAsync(CreateUserDto createUserDto, string role);
        Task<ResponseDto<LoginResponseDto>> LoginAsync(LoginDto loginDto);
        Task<ResponseDto<UserDto>> GetUserByIdAsync(string userId);
        Task<ResponseDto<List<UserDto>>> GetAllUsersAsync(ClaimsPrincipal currentUser);
        Task<ResponseDto<bool>> DeleteUserAsync(string userId);
        Task<ResponseDto<bool>> ReactivateUserAsync(string userId);
        Task<ResponseDto<bool>> UpdateUserAsync(string userId, UpdateUserDto userDto);
        Task<ResponseDto<bool>> ChangeUserPassword(ChangePasswordDto changePasswordDto);
        Task<ResponseDto<LoginResponseDto>> RefreshToken(RefreshTokenRequestDto refreshTokenDto);
    }
}
