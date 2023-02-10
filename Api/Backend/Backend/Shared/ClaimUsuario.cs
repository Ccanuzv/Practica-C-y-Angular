using System.Security.Claims;

namespace Backend.Shared
{
    public class ClaimUsuario
    {
        public static string UsuarioId(HttpContext httpContext)
        {
            string Id = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            return Id;
        }

    }
}
