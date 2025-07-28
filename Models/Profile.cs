using System;

namespace Models
{
    public class Profile
    {
        public Guid Id { get; set; }
        public string Username { get; set; } = null!;
        public Guid UserId { get; set; }
        public User User { get; set; } = null!;
    }
} 