using Backend.Data;
using Backend.Modelo.Entity;
using Backend.Modelo.Repositories.IRepository;
using System.Text;

namespace Backend.Modelo.Repositories.Repository
{
    public class UsuarioRepository: Repository<Usuario>, IUsuarioRepository
    {
        private readonly PracticaDB _context;
        private readonly ILogger<Usuario> _logger;

        public UsuarioRepository(PracticaDB context, ILogger<Usuario> logger) : base(context, logger)
        {
            _context = context;
            _logger = logger;
        }


        public string CrearPasswordHash(string usuarioPass, string usuarioId)
        {
            if (String.IsNullOrEmpty(usuarioPass))
            {
                return String.Empty;
            }

            System.Security.Cryptography.SHA512Managed HashTool = new System.Security.Cryptography.SHA512Managed();
            byte[] HashByte = Encoding.UTF8.GetBytes(string.Concat(usuarioPass, usuarioId));
            byte[] encryptedByte = HashTool.ComputeHash(HashByte);
            HashTool.Clear();

            return Convert.ToBase64String(encryptedByte);
        }

        public Usuario Login(string email, string pass)
        {
            Usuario usuario = _context.Usuarios.FirstOrDefault(w => w.UsuarioEmail.Equals(email));

            if (usuario != null)
            {
                string hash = VerificarPasswordHash(usuario.UsuarioId, pass);
                usuario = _context.Usuarios.FirstOrDefault(w => w.UsuarioEmail.Equals(email) && w.UsuarioPass.Equals(hash));
            }
            return usuario;
        }

        private string VerificarPasswordHash(string usuarioPass, string usuarioId)
        {

            if (String.IsNullOrEmpty(usuarioPass))
            {
                return String.Empty;
            }

            System.Security.Cryptography.SHA512Managed HashTool = new System.Security.Cryptography.SHA512Managed();
            byte[] HashByte = Encoding.UTF8.GetBytes(string.Concat(usuarioPass, usuarioId));
            byte[] encryptedByte = HashTool.ComputeHash(HashByte);
            HashTool.Clear();

            return Convert.ToBase64String(encryptedByte);
        }


    }
}
