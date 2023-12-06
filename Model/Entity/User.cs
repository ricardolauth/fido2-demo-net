using Microsoft.EntityFrameworkCore;
using System.Collections.ObjectModel;

namespace fido2_demo.Model.Entity
{
    [Index(nameof(Username), IsUnique = true)]
    public class User : BaseModel
    {
        public string? DisplayName { get; set; }
        public string Username { get; set; } = null!;
        public Collection<Credential> Credentials { get; set; } = [];
    }
}
