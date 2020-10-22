using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Users.Models;
using Users.Persisitence;

namespace Users.Services
{


    public class UserService : IUserService
    {
        private readonly ExpenseTrackerDBContext _dbcontext;

        private readonly ILogger<UserService> _logger;
        public UserService(ILogger<UserService> logger, ExpenseTrackerDBContext dbcontext)
        {
            _logger = logger;
            _dbcontext = dbcontext;
        }


        public bool IsValidUserCredentials(string userName, string password)
        {
            _logger.LogInformation($"Validating user [{userName}]");
            if (string.IsNullOrWhiteSpace(userName))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return false;
            }

            return _dbcontext.Users.Any(x => x.Username == userName && x.Password == password);
        }


        public bool IsAnExistingUser(string userName)
        {
            return _dbcontext.Users.Where(x => x.Username.Contains(userName)).Any();
        }

        public string GetUserRole(string userName)
        {
            var user = _dbcontext.Users.SingleOrDefault(x => x.Username == userName);

            if (user is null)
            {
                return string.Empty;
            }

            if (user.Role == "admin")
            {
                return UserRoles.Admin;
            }

            return UserRoles.BasicUser;
        }

        public async Task<IEnumerable<User>> GetUsers()
        {
            return await _dbcontext.Users.ToListAsync();
        }

    }

    public static class UserRoles
    {
        public const string Admin = nameof(Admin);
        public const string BasicUser = nameof(BasicUser);
    }
}
