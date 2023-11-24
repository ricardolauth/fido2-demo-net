using System.ComponentModel.DataAnnotations.Schema;

namespace fido2_demo.Model.Entity
{
    public class Credential
    {
        public string Id { get; set; } = null!;
        public Guid UserId { get; set; } 
        public string PublicKey { get; set; } = null!;
        public uint SignatureCounter { get; set; }
        public string CredType { get; set; } = null!;
        public Guid AaGuid { get; set; }
        public DateTime RegDate { get; set; }

        [ForeignKey(nameof(UserId))]
        public User User { get; set; } = null!;
    }
}
