using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;
using Users.Services;

namespace Users.Controllers
{
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly ILogger<AccountController> _logger;
        private readonly IUserService _userService;
        public UsersController(ILogger<AccountController> logger, IUserService userService)
        {
            _logger = logger;
            _userService = userService;
        }

        [HttpGet("GetUsers")]
        public async Task<IActionResult> Users()
        {
            _logger.LogInformation($"Retrieving users details");
            var users = await _userService.GetUsers();

            return Ok(users.Select(i => new { i.Id, i.Username }).ToArray());

        }

    }
}
