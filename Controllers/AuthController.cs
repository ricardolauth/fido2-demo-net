using fido2_demo.Authorization;
using fido2_demo.Model;
using fido2_demo.Model.Entity;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Claims;
using System.Text.Json;

namespace fido2_demo.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController(FidoDemoContext dbContext, IFido2 fido2, IMemoryCache memoryCache, IConfiguration configuration, IJwtUtils jwtUtils) : ControllerBase
    {
        private readonly FidoDemoContext _dbContext = dbContext;
        private readonly IFido2 _fido2 = fido2;
        private readonly IMemoryCache _memoryCache = memoryCache;
        private readonly IConfiguration _configuration = configuration;
        private readonly IJwtUtils _jwtUtils = jwtUtils;

        [HttpPost("creationOptions", Name = nameof(CreatePublicKeyCredentialCreationOptions))]
        public async Task<CredentialCreateOptions> CreatePublicKeyCredentialCreationOptions([FromBody] User user)
        {
            try
            {
                var actor = HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Actor)?.Value;

                // lookup the username in th db
                var userDb = await _dbContext.Users.AsNoTracking()
                    .Include(u => u.Credentials)
                    .FirstOrDefaultAsync(u => u.Username == user.Username);

                // if the user  exist we override
                if (userDb != null)
                {
                    if(actor != null && Guid.Parse(actor) == userDb.Id)
                    {
                        user = userDb;
                    }
                    else
                    {
                        return new CredentialCreateOptions { Status = "error", ErrorMessage = "Userame already exists" };
                    }                    
                }
                else
                {
                    if (string.IsNullOrEmpty(user.Username))
                    {
                        user.Username = $"Nameless user created on {DateTime.UtcNow}";
                    }

                    user.Id = Guid.NewGuid();
                }

                // get all previous registred credentialDescriptors for the current user
                var excludeCredentials = user.Credentials.Select(c => new PublicKeyCredentialDescriptor(GetBytes(c.Id))).ToList();


                // 3. Create options -- defaults are the recommandation of WebAuthn?
                var authenticatorSelection = new AuthenticatorSelection
                {
                    AuthenticatorAttachment = null, // if present authenticators only the set type of authenticators is allowed e.g. platform. Its recommended to allow both.
                    RequireResidentKey = true, // this forces the authenticators to store the user handle -> which can be used for usernameless authentication
                    UserVerification = UserVerificationRequirement.Preferred // recommend to use preferred
                };

                // create a fido2 user object -> required by the lib
                var fidoUser = new Fido2User
                {
                    DisplayName = user.DisplayName,
                    Name = user.Username,
                    Id = user.Id.ToByteArray() // byte representation of userID is required
                };

                var options = _fido2.RequestNewCredential(fidoUser, excludeCredentials, authenticatorSelection, AttestationConveyancePreference.Direct);
                _memoryCache.Set($"{nameof(CredentialCreateOptions)}/{GetString(options.Challenge)}", options, TimeSpan.FromMilliseconds(options.Timeout));

                return options;
            } catch (Exception ex)
            {
                return new CredentialCreateOptions { Status = "error", ErrorMessage = ex.Message };
            }
        }

        [HttpPost("createCredential", Name = nameof(CreateCredential))]
        public async Task<ActionResult<string>> CreateCredential([FromBody] AuthenticatorAttestationRawResponse rawResponse)
        {
            var response = JsonSerializer.Deserialize<AuthenticatorResponse>(rawResponse.Response.ClientDataJson);
            if (response == null || !_memoryCache.TryGetValue<CredentialCreateOptions>($"{nameof(CredentialCreateOptions)}/{GetString(response.Challenge)}", out var options))
            {
                return BadRequest("Can't find options, maybe expired");
            }

            if(options == null)
            {
                return BadRequest("Options are null");
            }

            // 2. Create callback so that lib can verify credential id is unique to this user
            async Task<bool> callback(IsCredentialIdUniqueToUserParams args, CancellationToken cancellationToken)
            {
                var credentialId = GetString(args.CredentialId);
                var credentialExist = await _dbContext.Credentials.AsNoTracking().AnyAsync(c => c.Id == credentialId, cancellationToken: cancellationToken);
                return !credentialExist;
            }


            // 2. Verify and make the credentials
            var result = await _fido2.MakeNewCredentialAsync(rawResponse, options, callback);

            if (result.Status is "error" || result.Result is null)
            {
                // return BadRequest(result.ErrorMessage ?? string.Empty);
                return BadRequest(result.ErrorMessage ?? "Verification returned null");
            }

            var userExits = await _dbContext.Users.AsNoTracking().AnyAsync(u => u.Username == result.Result.User.Name);
            if (!userExits)
            {
                User user = new()
                {
                    Id = new Guid(result.Result.User.Id),
                    Username = result.Result.User.Name,
                    DisplayName = result.Result.User.DisplayName
                };

                _dbContext.Users.Add(user);
            }
          

            var credential = new Credential
            {
                Id = GetString(result.Result.CredentialId),
                UserId = new Guid(result.Result.User.Id),
                PublicKey = GetString(result.Result.PublicKey),
                SignatureCounter = result.Result.Counter,
                RegDate = DateTime.UtcNow,
                AaGuid = result.Result.Aaguid,
                CredType = result.Result.CredType
            };

            _dbContext.Credentials.Add(credential);
            await _dbContext.SaveChangesAsync();

            var token = _jwtUtils.GenerateToken(credential.UserId);
            return Ok(token is null ? throw new Exception("Token couldn't be created") : $"Bearer {token}");
        }

        [HttpGet("assertion-options")]
        public async Task<AssertionOptions> MakeAssertionOptions([FromQuery] string? username)
        {
            try
            {
                var allowedCredentials = new List<PublicKeyCredentialDescriptor>();
                if (!string.IsNullOrEmpty(username))
                {
                    // 1. Get user and their credentials from DB
                    var user = await _dbContext.Users.Include(x => x.Credentials).FirstOrDefaultAsync(x => x.Username == username);

                    if (user != null)
                        allowedCredentials = user.Credentials.Select(c => new PublicKeyCredentialDescriptor(GetBytes(c.Id))).ToList();
                }


                // 2. Create options (usernameless users will be prompted by their device to select a credential from their own list)
                var options = _fido2.GetAssertionOptions(allowedCredentials, UserVerificationRequirement.Preferred);

                // 4. Temporarily store options, session/in-memory cache/redis/db
                _memoryCache.Set($"{nameof(AssertionOptions)}/{GetString(options.Challenge)}", 
                    options, 
                    TimeSpan.FromMilliseconds(options.Timeout));

                // 5. return options to client
                return options;
            }
            catch (Exception e)
            {
                return new AssertionOptions { Status = "error", ErrorMessage = e.Message };
            }
        }

        [HttpPost("assertion")]
        public async Task<string> MakeAssertionAsync([FromBody] AuthenticatorAssertionRawResponse clientResponse,
       CancellationToken cancellationToken)
        {
            // 1. Get the assertion options we sent the client remove them from memory so they can't be used again
            var response = JsonSerializer.Deserialize<AuthenticatorResponse>(clientResponse.Response.ClientDataJson) ?? throw new Exception("Could not deserialize client data");
            var key = $"{nameof(AssertionOptions)}/{GetString(response.Challenge)}";
            if (!_memoryCache.TryGetValue<AssertionOptions>($"{nameof(AssertionOptions)}/{GetString(response.Challenge)}", out var options))
            {
                throw new Exception("Challenge not found, please get a new one via GET /assertion-options");
            }
            _memoryCache.Remove(key);

            if (options is null)
            {
                throw new Exception("AssertionOptions are null");
            }

            // 2. Get registered credential from database
            var credentialId = GetString(clientResponse.Id);
            var credential = await _dbContext.Credentials.FirstOrDefaultAsync(c => c.Id == credentialId, cancellationToken: cancellationToken) 
                ?? throw new Exception("Unkown Credential");

            // 2. Create callback so that lib can verify credential id is unique to this user
            async Task<bool> callback(IsUserHandleOwnerOfCredentialIdParams args, CancellationToken cancellationToken)
            {
                var userId = new Guid(args.UserHandle);
                var credentialId = GetString(args.CredentialId);
                var credentialExist = await _dbContext.Credentials.AsNoTracking().AnyAsync(c => c.Id == credentialId && c.UserId == userId, cancellationToken: cancellationToken);
                return credentialExist;
            }

            // 3. Make the assertion
            var res = await _fido2.MakeAssertionAsync(
                clientResponse,
                options,
                storedPublicKey: GetBytes(credential.PublicKey),
                storedSignatureCounter: credential.SignatureCounter,
                isUserHandleOwnerOfCredentialIdCallback: callback,
                cancellationToken: cancellationToken);

            // 4. Store the updated counter
            if (res.Status is not "ok")
            {
                throw new Exception(res.ErrorMessage);
            }

            credential.SignatureCounter = res.Counter;
            _dbContext.Update(credential);
            await _dbContext.SaveChangesAsync(cancellationToken);

            var token = _jwtUtils.GenerateToken(credential.UserId);

            return token is null ? throw new Exception("Token couldn't be created") : $"Bearer {token}";
        }

        // Helpers
        private static string GetString(byte[] arr)
        {
            return Convert.ToBase64String(arr);
        }

        private static byte[] GetBytes(string str)
        {
            return Convert.FromBase64String(str);
        }
    }
}
