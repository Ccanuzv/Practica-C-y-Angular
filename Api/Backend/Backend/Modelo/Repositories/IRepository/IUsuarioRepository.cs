using Backend.Modelo.Entity;

namespace Backend.Modelo.Repositories.IRepository
{
    public interface IUsuarioRepository: IRepository<Usuario>
    {
        string CrearPasswordHash(string usuarioPass, string usuarioId);
        Usuario Login(string email, string pass);
    }
}
