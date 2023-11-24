using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace fido2_demo.Controllers
{
    [ApiController]
    [Route("api/home")]
    [Produces("application/json")]
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [HttpGet( Name = nameof(GetTest))]
        public ActionResult<Dictionary<string, string>> GetTest()
        {
            var identity = (ClaimsIdentity)Request.HttpContext.User.Identity;
            var claims = identity.Claims.ToDictionary(x => x.Type, x => x.Value);
            return Ok(claims);
        }

        
    }
}
