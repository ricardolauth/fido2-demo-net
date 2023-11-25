using System.Security.Claims;
using fido2_demo.Model;
using fido2_demo.Model.Entity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Web;

namespace fido2_demo.Controllers
{
    [ApiController]
    [Route("api/me")]
    [Produces("application/json")]
    [Authorize]
    public class MeController : Controller
    {
        private readonly ILogger<MeController> _logger;
        private readonly FidoDemoContext _dbContext;

        public MeController(ILogger<MeController> logger, FidoDemoContext dbContext)
        {
            _logger = logger;
            _dbContext = dbContext;
        }

        [HttpGet(Name = nameof(MeAsync))]
        public async Task<ActionResult<User>> MeAsync()
        {
            var identity = (ClaimsIdentity?) Request.HttpContext.User.Identity;
            var actor = identity?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Actor)?.Value;

            if (actor == null)
            {
                return BadRequest("Could not access your identity");
            }

            var user = await _dbContext.Users.AsNoTracking()
                .Include(u => u.Credentials)
                .FirstOrDefaultAsync(u => u.Id == Guid.Parse(actor));

            if (user == null)
            {
                return BadRequest("Could not retrieve user from database");
            }

            var credentials = user?.Credentials.Select(c => new Credential()
            {
                AaGuid = c.AaGuid,
                CredType = c.CredType,
                Id = c.Id,
                PublicKey = c.PublicKey,
                RegDate = c.RegDate,
                SignatureCounter = c.SignatureCounter,
                User = null, // circular reference -> crashes in json serialization
                UserId = c.UserId

            });

            user!.Credentials = new System.Collections.ObjectModel.Collection<Credential>(credentials?.ToList() ?? []);

            return Ok(user);
        }

        [HttpDelete("credentials/{id}", Name = nameof(DeleteMyCredentialAsync))]
        public async Task<ActionResult> DeleteMyCredentialAsync([FromRoute] string id)
        {
            var identity = (ClaimsIdentity?)Request.HttpContext.User.Identity;
            var actor = identity?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Actor)?.Value;

            if (actor == null)
            {
                return BadRequest("Could not access your identity");
            }

            var decodedId = HttpUtility.UrlDecode(id); // some characters like / aren't allowed to be used in url parameters because they have a special meaning in an url context
            var credential = await _dbContext.Credentials.AsNoTracking()
                .FirstOrDefaultAsync(c => c.UserId == Guid.Parse(actor) && c.Id == decodedId);

            if (credential == null)
            {
                return BadRequest($"Could not retrieve your credential with id {id} from the database");
            }

            _dbContext.Credentials.Remove(credential);
            await _dbContext.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete(Name = nameof(DeleteMeAsync))]
        public async Task<ActionResult> DeleteMeAsync()
        {
            var identity = (ClaimsIdentity?)Request.HttpContext.User.Identity;
            var actor = identity?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Actor)?.Value;

            if (actor == null)
            {
                return BadRequest("Could not access your identity");
            }

            var user = await _dbContext.Users.AsNoTracking()
                .Include(u => u.Credentials)
                .FirstOrDefaultAsync(u => u.Id == Guid.Parse(actor));

            if (user == null)
            {
                return BadRequest("Could not retrieve user from database");
            }

            _dbContext.Credentials.RemoveRange(user.Credentials);
            _dbContext.Users.Remove(user);
            await _dbContext.SaveChangesAsync();

            return NoContent();
        }
    }
}
