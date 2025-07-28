using Microsoft.AspNetCore.Authorization;
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
public class ProfileController : ControllerBase
{
    private readonly GameDbContext _db;
    private readonly IPasswordHasher<User> _hasher;
    private readonly IConfiguration _config;

    public ProfileController(GameDbContext db, IPasswordHasher<User> hasher, IConfiguration config)
    {
        _db = db;
        _hasher = hasher;
        _config = config;
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> Create(ProfileCreateRequest req)
    {
        var userId = GetUserIdFromClaims(User);
        if (userId == null) return Unauthorized();
        var profile = new Profile
        {
            Id = Guid.NewGuid(),
            Username = req.Username,
            UserId = userId.Value
        };
        _db.Profiles.Add(profile);
        await _db.SaveChangesAsync();
        return Ok(profile);
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> List()
    {
        var userId = GetUserIdFromClaims(User);
        if (userId == null) return Unauthorized();
        var profiles = await _db.Profiles.Where(p => p.UserId == userId.Value).ToListAsync();
        return Ok(profiles);
    }

    [Authorize]
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
    {
        var userId = GetUserIdFromClaims(User);
        if (userId == null) return Unauthorized();
        var profile = await _db.Profiles.FirstOrDefaultAsync(p => p.Id == id && p.UserId == userId.Value);
        if (profile == null) return NotFound();
        return Ok(profile);
    }

    [Authorize]
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, ProfileUpdateRequest req)
    {
        var userId = GetUserIdFromClaims(User);
        if (userId == null) return Unauthorized();
        var profile = await _db.Profiles.FirstOrDefaultAsync(p => p.Id == id && p.UserId == userId.Value);
        if (profile == null) return NotFound();
        profile.Username = req.Username;
        await _db.SaveChangesAsync();
        return Ok(profile);
    }

    [Authorize]
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var userId = GetUserIdFromClaims(User);
        if (userId == null) return Unauthorized();
        var profile = await _db.Profiles.FirstOrDefaultAsync(p => p.Id == id && p.UserId == userId.Value);
        if (profile == null) return NotFound();
        _db.Profiles.Remove(profile);
        await _db.SaveChangesAsync();
        return Ok();
    }

    [HttpPost("login")]
    public async Task<IActionResult> ProfileLogin(ProfileLoginRequest req)
    {
        var profile = await _db.Profiles.Include(p => p.User).FirstOrDefaultAsync(p => p.Username == req.ProfileUsername);
        if (profile == null) return Unauthorized();
        var user = profile.User;
        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);
        if (result != PasswordVerificationResult.Success) return Unauthorized();
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

    private Guid? GetUserIdFromClaims(ClaimsPrincipal user)
    {
        var sub = user.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (Guid.TryParse(sub, out var guid)) return guid;
        return null;
    }
} 