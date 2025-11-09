using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Project.Data.Models;
using Project.Dtos.Requests;
using Project.Services.Interface;

namespace Project.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUser _userService;

        public AuthController(IUser userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterUser([FromBody] CreateUserDto createUserDto)
        {
            var result = await _userService.CreateUserAsync(createUserDto);
            return Ok(result);
        }

        [HttpPost("registerUserWithRole")]
        [Authorize(Roles = $"{RoleTypes.SuperAdmin}")]
        public async Task<IActionResult> RegisterUserWithRole([FromBody] CreateUserDto createUserWithRoleDto, string role)
        {
            var result = await _userService.CreateUserWithRoleAsync(createUserWithRoleDto, role);
            return Ok(result);
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var result = await _userService.LoginAsync(loginDto);
            return Ok(result);
        }

        [HttpPost("refreshtoken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto refreshTokenDto)
        {
            var result = await _userService.RefreshToken(refreshTokenDto);
            return Ok(result);
        }
    }
}
