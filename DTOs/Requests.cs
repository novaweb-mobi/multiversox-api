namespace DTOs;

public record RegisterRequest(string Name, string Password);
public record LoginRequest(string Name, string Password);
public record ProfileCreateRequest(string Username);
public record ProfileUpdateRequest(string Username);
public record ProfileLoginRequest(string ProfileUsername, string Password); 