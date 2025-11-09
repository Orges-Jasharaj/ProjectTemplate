using Hangfire;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Project.Data;
using Project.Data.Models;
using Project.Dtos.Requests;
using Project.Dtos.Responses;
using Project.Services.Interface;
using System.Security.Claims;

namespace Project.Services.Implementation
{
    public class UserService : IUser
    {
        private readonly UserManager<User> _userManager;
        private readonly IUserStore<User> _userStore;
        private readonly IUserEmailStore<User> _emailStore;
        private readonly SignInManager<User> _signInManager;
        private readonly ITokenService _tokenService;
        private readonly ILogger<UserService> _logger;
        private readonly AppDbContext _appDbContext;
        //private readonly IEmailSender _emailSender;

        public UserService(
            UserManager<User> userManager,
            IUserStore<User> userStore,
            IUserEmailStore<User> emailStore,
            SignInManager<User> signInManager,
            ITokenService tokenService,
            ILogger<UserService> logger,
            AppDbContext appDbContext
            //IEmailSender emailSender
            )
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = emailStore;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _logger = logger;
            _appDbContext = appDbContext;
            //_emailSender = emailSender;
        }

        [AutomaticRetry(Attempts = 3)]
        public async Task<ResponseDto<bool>> CreateUserAsync(CreateUserDto createUserDto)
        {
            try
            {
                var userExists = await _userManager.FindByEmailAsync(createUserDto.Email);
                if (userExists != null)
                {
                    _logger.LogInformation($"Attempt to create user with existing email {createUserDto.Email}");
                    return ResponseDto<bool>.Failure("User already exists");
                }
                var user = new User
                {
                    FirstName = createUserDto.FirstName,
                    LastName = createUserDto.LastName,
                    DateOfBirth = createUserDto.DateOfBirth,
                    isActive = true,

                };
                await _userStore.SetUserNameAsync(user, createUserDto.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, createUserDto.Email, CancellationToken.None);

                var result = await _userManager.CreateAsync(user, createUserDto.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation($"User {user.Email} created successfully");
                    await _userManager.AddToRoleAsync(user, RoleTypes.User);


                    //BackgroundJob.Enqueue(() =>
                    //_emailSender.SendEmail(user.Email, "Welcome to E-Commerce Shop", $"Hello {createUserDto.FirstName}, welcome to our e-commerce platform!"));

                    //BackgroundJob.Enqueue(() =>
                    //_emailSender.SendEmailWithTemplateAsync(user.Email, "Welcome to E - Commerce Shop", user.FirstName, user.LastName));

                    //BackgroundJob.Enqueue(() => SendEmail(createUserDto.FirstName, createUserDto.Email));

                    return ResponseDto<bool>.SuccessResponse(true, "User created successfully");

                }
                var errors = result.Errors.Select(e => new ApiError
                {
                    ErrorCode = e.Code,
                    ErrorMessage = e.Description
                }).ToList();


                return ResponseDto<bool>.Failure("User creation failed", errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while creating user with email {Email}", createUserDto.Email);
                return ResponseDto<bool>.Failure("An error occurred while creating user");
            }

        }

        //public async Task<bool> SendEmail(string FirstName, string email)
        //{
        //    await Task.Delay(2000);
        //    Console.WriteLine($"Email sent to {FirstName} with email {email}");
        //    return true;
        //}


        public async Task<ResponseDto<bool>> DeleteUserAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ResponseDto<bool>.Failure("User not found.");
            }

            user.isActive = false;
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation($"User {user.Email} deactivated successfully");
                return ResponseDto<bool>.SuccessResponse(true, "User deactivated successfully.");
            }

            var errors = result.Errors.Select(e => new ApiError
            {
                ErrorCode = e.Code,
                ErrorMessage = e.Description
            }).ToList();

            _logger.LogWarning($"Failed to deactivate user {user.Email}: {string.Join(", ", errors.Select(err => err.ErrorMessage))}");
            return ResponseDto<bool>.Failure("User deactivation failed.", errors);
        }


        public async Task<ResponseDto<bool>> ReactivateUserAsync(string userId)
        {
            var user = await _appDbContext.Users
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(u => u.Id == userId);
            if (user == null)
            {
                return ResponseDto<bool>.Failure("User not found.");
            }

            user.isActive = true;
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation($"User {user.Email} reactivated successfully");
                return ResponseDto<bool>.SuccessResponse(true, "User reactivated successfully.");
            }

            var errors = result.Errors.Select(e => new ApiError
            {
                ErrorCode = e.Code,
                ErrorMessage = e.Description
            }).ToList();

            return ResponseDto<bool>.Failure("User reactivation failed.", errors);
        }


        public async Task<ResponseDto<List<UserDto>>> GetAllUsersAsync(ClaimsPrincipal currentUser)
        {
            try
            {
                IQueryable<User> query = _appDbContext.Users;

                if (currentUser.IsInRole(RoleTypes.Admin) || currentUser.IsInRole(RoleTypes.SuperAdmin))
                {
                    query = query.IgnoreQueryFilters();
                }

                var users = await query
                    .Select(u => new UserDto
                    {
                        Id = u.Id,
                        FirstName = u.FirstName,
                        LastName = u.LastName,
                        Email = u.Email,
                        DateOfBirth = u.DateOfBirth,
                        isActive = u.isActive
                    })
                    .ToListAsync();

                return ResponseDto<List<UserDto>>.SuccessResponse(users, "Users retrieved successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving users");
                return ResponseDto<List<UserDto>>.Failure("An error occurred while retrieving users");
            }
        }




        public async Task<ResponseDto<UserDto>> GetUserByIdAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ResponseDto<UserDto>.Failure("User not found.");
            }
            var userDto = new UserDto
            {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                DateOfBirth = user.DateOfBirth,
                Email = user.Email,
            };
            return ResponseDto<UserDto>.SuccessResponse(userDto, "User retrieved successfully.");

        }

        public async Task<ResponseDto<LoginResponseDto>> LoginAsync(LoginDto loginDto)
        {
            var userExists = await _userManager.FindByEmailAsync(loginDto.Email);
            if (userExists == null)
            {
                return ResponseDto<LoginResponseDto>.Failure("User does not exist");
            }
            var result = await _signInManager.PasswordSignInAsync(userExists, loginDto.Password, false, false);
            if (result.Succeeded)
            {
                var roles = await _userManager.GetRolesAsync(userExists);


                var token = _tokenService.GenerateAccessToken(userExists, roles.ToList());
                var refreshToken = _tokenService.GenerateRrefreshToken();
                userExists.RefreshToken = refreshToken.RefreshToken;
                userExists.RefreshTokenExpiryTime = refreshToken.RefreshTokenExpiryDate;

                await _userManager.UpdateAsync(userExists);

                var rolesList = roles.ToList();
                var loginResponse = new LoginResponseDto
                {
                    DisplayName = $"{userExists.FirstName} {userExists.LastName}",
                    Email = userExists.Email,
                    AccessToken = token,
                    RefreshToken = refreshToken.RefreshToken,
                    RefreshTokenExpiryTime = refreshToken.RefreshTokenExpiryDate,
                    Roles = rolesList
                };

                //BackgroundJob.Enqueue(() =>
                //_emailSender.SendEmail(userExists.Email, "Login Notification", $"Hello {userExists.FirstName}, you have successfully logged in at {DateTime.UtcNow}."));
                return ResponseDto<LoginResponseDto>.SuccessResponse(loginResponse, "Login successful");

            }

            return ResponseDto<LoginResponseDto>.Failure("Login failed, please check your credentials");
        }

        public async Task<ResponseDto<bool>> UpdateUserAsync(string userId, UpdateUserDto userDto)
        {
            var user = await _userManager.FindByIdAsync(userId.ToString());
            if (user == null)
            {
                return ResponseDto<bool>.Failure("User not found.");
            }

            user.FirstName = userDto.FirstName;
            user.LastName = userDto.LastName;
            user.DateOfBirth = userDto.DateOfBirth;

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                _logger.LogInformation($"User {user.Email} updated successfully");
                //BackgroundJob.Enqueue(() =>
                //_emailSender.SendEmail(user.Email, "Profile Update Notification", $"Hello {user.FirstName}, your profile was updated successfully at {DateTime.UtcNow}."));
                return ResponseDto<bool>.SuccessResponse(true, "User updated successfully.");
            }

            var errors = result.Errors.Select(e => new ApiError
            {
                ErrorCode = e.Code,
                ErrorMessage = e.Description
            }).ToList();

            _logger.LogInformation($"Failed to update user {user.Email}: {string.Join(", ", errors.Select(err => err.ErrorMessage))}");
            return ResponseDto<bool>.Failure("User update failed.", errors);
        }

        public async Task<ResponseDto<bool>> ChangeUserPassword(ChangePasswordDto changePasswordDto)
        {
            var user = await _userManager.FindByIdAsync(changePasswordDto.UserId);
            if (user == null)
            {
                return ResponseDto<bool>.Failure("User does not exist");
            }

            var result = await _userManager.ChangePasswordAsync(user, changePasswordDto.OldPassword, changePasswordDto.NewPassword);
            if (result.Succeeded)
            {
                _logger.LogInformation($"User {user.Email} changed password successfully");
                //BackgroundJob.Enqueue(() =>
                //_emailSender.SendEmail(user.Email, "Password Change Notification", $"Hello {user.FirstName}, your password was changed successfully at {DateTime.UtcNow}."));
                return ResponseDto<bool>.SuccessResponse(true, "Password changed successfully");
            }
            var errors = result.Errors.Select(e => new ApiError
            {
                ErrorCode = e.Code,
                ErrorMessage = e.Description
            }).ToList();
            _logger.LogWarning($"Failed to change password for user {user.Email}: {string.Join(", ", errors.Select(err => err.ErrorMessage))}");
            return ResponseDto<bool>.Failure("Password change failed", errors);


        }

        public async Task<ResponseDto<LoginResponseDto>> RefreshToken(RefreshTokenRequestDto refreshTokenDto)
        {
            var claimPrincipal = _tokenService.GetClaimsPrincipal(refreshTokenDto.AccessToken);
            if (claimPrincipal == null)
            {
                return ResponseDto<LoginResponseDto>.Failure("Invalid access token");
            }

            var userId = claimPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            // Fix: Check user first before accessing its properties
            if (user == null)
            {
                return ResponseDto<LoginResponseDto>.Failure("User does not exist");
            }

            if (user.RefreshToken != refreshTokenDto.RefreshToken || user.RefreshTokenExpiryTime < DateTime.UtcNow)
            {
                return ResponseDto<LoginResponseDto>.Failure("Invalid or expired refresh token");
            }

            var roles = await _userManager.GetRolesAsync(user);


            var token = _tokenService.GenerateAccessToken(user, roles.ToList());
            var refreshToken = _tokenService.GenerateRrefreshToken();
            user.RefreshToken = refreshToken.RefreshToken;
            user.RefreshTokenExpiryTime = refreshToken.RefreshTokenExpiryDate;

            await _userManager.UpdateAsync(user);

            var rolesList = roles.ToList();
            var loginResponse = new LoginResponseDto
            {
                DisplayName = $"{user.FirstName} {user.LastName}",
                Email = user.Email,
                AccessToken = token,
                RefreshToken = refreshToken.RefreshToken,
                RefreshTokenExpiryTime = refreshToken.RefreshTokenExpiryDate,
                Roles = rolesList
            };
            return ResponseDto<LoginResponseDto>.SuccessResponse(loginResponse, "Token refreshed successfully");

        }



        public async Task<ResponseDto<bool>> CreateUserWithRoleAsync(CreateUserDto createUserDto, string role)
        {
            try
            {
                var allowedRoles = new[] { RoleTypes.SuperAdmin, RoleTypes.Admin };

                if (!allowedRoles.Contains(role))
                {
                    return ResponseDto<bool>.Failure($"Invalid role: {role}. Allowed roles are: {string.Join(", ", allowedRoles)}");
                }


                var userExists = await _userManager.FindByEmailAsync(createUserDto.Email);
                if (userExists != null)
                {
                    _logger.LogInformation($"Attempt to create user with existing email {createUserDto.Email}");
                    return ResponseDto<bool>.Failure("User already exists");
                }

                var user = new User
                {
                    FirstName = createUserDto.FirstName,
                    LastName = createUserDto.LastName,
                    DateOfBirth = createUserDto.DateOfBirth,
                    isActive = true
                };

                await _userStore.SetUserNameAsync(user, createUserDto.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, createUserDto.Email, CancellationToken.None);

                var result = await _userManager.CreateAsync(user, createUserDto.Password);
                if (result.Succeeded)
                {
                    _logger.LogInformation($"User {user.Email} created successfully");
                    await _userManager.AddToRoleAsync(user, role);
                    //BackgroundJob.Enqueue(() => SendEmail(createUserDto.FirstName, createUserDto.Email));

                    //BackgroundJob.Enqueue(() =>
                    //_emailSender.SendEmail(user.Email, "Welcome to E-Commerce Shop", $"Hello {createUserDto.FirstName}, welcome to our e-commerce platform as a {role}!"));
                    return ResponseDto<bool>.SuccessResponse(true, $"User created successfully as {role}");
                }

                var errors = result.Errors.Select(e => new ApiError
                {
                    ErrorCode = e.Code,
                    ErrorMessage = e.Description
                }).ToList();

                return ResponseDto<bool>.Failure("User creation failed", errors);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while creating user with email {Email}", createUserDto.Email);
                return ResponseDto<bool>.Failure("An error occurred while creating user");
            }
        }
    }
}
