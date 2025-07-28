using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Data;
using Models;
using DTOs;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly GameDbContext _db;
    private readonly IPasswordHasher<User> _hasher;
    private readonly IConfiguration _config;

    public UserController(GameDbContext db, IPasswordHasher<User> hasher, IConfiguration config)
    {
        _db = db;
        _hasher = hasher;
        _config = config;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest req)
    {
        if (await _db.Users.AnyAsync(u => u.Name == req.Name))
            return BadRequest("Username already exists");
        var user = new User
        {
            Id = Guid.NewGuid(),
            Name = req.Name
        };
        user.PasswordHash = _hasher.HashPassword(user, req.Password);
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return Ok();
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest req)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Name == req.Name);
        if (user == null)
            return Unauthorized();
        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);
        if (result != PasswordVerificationResult.Success)
            return Unauthorized();

        var jwtSettings = _config.GetSection("Jwt");
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Name)
        };
        var keyString = jwtSettings["Key"];
        if (string.IsNullOrEmpty(keyString))
            throw new InvalidOperationException("JWT Key is not configured.");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(12),
            signingCredentials: creds
        );
        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        return Ok(new { token = tokenString });
    }
} 