using System;
using System.Collections.Generic;

namespace Models
{
    public class User
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = null!;
        public string PasswordHash { get; set; } = null!;
        public ICollection<Profile> Profiles { get; set; } = new List<Profile>();
    }
} 