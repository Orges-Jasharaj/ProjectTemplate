using Hangfire;
using Hangfire.Dashboard.BasicAuthorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Project.Data;
using Project.Data.Models;
using Project.Dtos.System;
using Project.Middleware;
using Project.Seed;
using Project.Services.Implementation;
using Project.Services.Interface;
using Serilog;
using System.Security.Claims;
using System.Text;

namespace Project
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddHangfire(conf =>
            {
                conf.UseSqlServerStorage(builder.Configuration.GetConnectionString("DefaultConnection"));
            });

            builder.Services.AddHangfireServer();

            builder.Services.AddDbContext<AppDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            builder.Services.AddIdentity<User, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddScoped<IUserEmailStore<User>>(sp =>
          (IUserEmailStore<User>)sp.GetRequiredService<IUserStore<User>>());

            builder.Host.UseSerilog((context, configuration) =>
            {
                configuration.ReadFrom.Configuration(context.Configuration);

            });

            builder.Services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                    Description = "Enter  your token in the text input below.\n\nExample: '12345abcdef'",
                });

                c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
             {
                 {
                     new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                     {
                         Reference = new Microsoft.OpenApi.Models.OpenApiReference
                         {
                             Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                             Id = "Bearer"
                         }
                     },
                     new string[] { }
                 }
             });
            });

            builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));

            var jwtSettings = new JwtSettings();
            builder.Configuration.GetSection(JwtSettings.SectionName).Bind(jwtSettings);

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidAudience = jwtSettings.Audience,
                    ClockSkew = TimeSpan.Zero,
                    RoleClaimType = ClaimTypes.Role,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey))
                };
            });

            builder.Services.AddScoped<IUser, UserService>();
            builder.Services.AddScoped<ITokenService, TokenService>();
            builder.Services.AddScoped<CurrentUserService>();

            builder.Services.AddHttpContextAccessor();


            builder.Services.AddAuthorization();


            builder.Services.AddControllers();
            // Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
            builder.Services.AddOpenApi();

            var app = builder.Build();

            SeedData.InitializeAsync(app.Services).GetAwaiter().GetResult();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.MapOpenApi();
                app.UseSwagger();
                app.UseSwaggerUI(app =>
                {
                    app.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity API V1");
                });
            }

            app.UseHttpsRedirection();

            app.UseMiddleware<ExceptionHandlingMiddleware>();
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.UseHangfireDashboard("/hangfire", new DashboardOptions
            {
                Authorization = new[]
                {
                    new BasicAuthAuthorizationFilter(
                        new BasicAuthAuthorizationFilterOptions
                        {
                            SslRedirect = false,
                            RequireSsl = false,
                            LoginCaseSensitive = true,
                            Users = new[]
                            {
                                new BasicAuthAuthorizationUser
                                {
                                    Login = "admin",
                                    PasswordClear = "password"
                                }
                            }
                        })
                }
            });

            app.Run();
        }
    }
}
