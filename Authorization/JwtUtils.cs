using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace fido2_demo.Authorization
{
    public interface IJwtUtils
    {
        public string GenerateToken(Guid userId);
    }

    public class JwtUtils : IJwtUtils
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly SigningCredentials _signingCredentials;

        public JwtUtils(IConfiguration configuration, IHttpContextAccessor contextAccessor)
        {
            _configuration = configuration;
            _contextAccessor = contextAccessor;
            string secret = _configuration.GetValue<string>("secret") ?? throw new Exception("secret not provided");
            _signingCredentials = new(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)), SecurityAlgorithms.HmacSha256);
        }

        public string GenerateToken(Guid userId)
        {
            var actor = userId.ToString();
            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateEncodedJwt(
                _contextAccessor.HttpContext?.Request.Host.Host,
                _contextAccessor.HttpContext?.Request.Headers.Referer,
                new ClaimsIdentity(new Claim[] { new(ClaimTypes.Actor, actor) }),
                DateTime.Now.Subtract(TimeSpan.FromMinutes(1)),
                DateTime.Now.AddDays(1),
                DateTime.Now,
                _signingCredentials,
                null);

            return token ?? throw new Exception("Couldn't create the token");
        }
    }
}
