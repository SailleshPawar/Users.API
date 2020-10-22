using System.Collections.Generic;
using System.Threading.Tasks;
using Users.Models;

namespace Users.Services
{
    public interface IUserService
    {
        bool IsAnExistingUser(string userName);
        bool IsValidUserCredentials(string userName, string password);
        string GetUserRole(string userName);

        Task<IEnumerable<User>> GetUsers();
    }
}
