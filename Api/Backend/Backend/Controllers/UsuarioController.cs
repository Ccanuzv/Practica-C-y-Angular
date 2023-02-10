using Backend.Data;
using Backend.Modelo.Repositories.IRepository;
using Microsoft.AspNetCore.Mvc;
using Backend.Modelo.ViewModels;
using Backend.Modelo.Entity;
using Backend.Shared;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Backend.Controllers
{
    [Route("Core/[controller]")]
    [ApiController]
    public class UsuarioController : Controller
    {
        private readonly IUsuarioRepository _usuarioRepository;
        private readonly ILogger<UsuarioController> _logger;
        private readonly IConfiguration _config;
        private readonly PracticaDB _context;

        public UsuarioController(IUsuarioRepository usuarioRepository,
                                 ILogger<UsuarioController> logger,
                                 IConfiguration config,
                                 PracticaDB context)
        {
            _usuarioRepository = usuarioRepository;
            _logger = logger;
            _config = config;
            _context = context;
        }

        [HttpPost]
        public ActionResult PostUsuario(UsuarioCrearViewModel model)
        {
            using (var transaction = _context.Database.BeginTransaction())
            {
                var usuariobusca = _usuarioRepository.GetAll().FirstOrDefault(w => w.UsuarioEmail.Equals(model.Email));
                //validad si hay otro nick igual
                if (usuariobusca != null)
                {
                    return Unauthorized("Acción invalida");
                }

                try
                {
                    Usuario usuario = new Usuario();
                    usuario.UsuarioId = UiddGenetor.uidd();
                    string passHah = _usuarioRepository.CrearPasswordHash(usuario.UsuarioId, model.Password);
                    usuario.UsuarioNombre = model.Nombre;
                    usuario.UsuarioPass = passHah;
                    usuario.UsuarioEmail = model.Email;
                    usuario.UsuarioFechaNacimiento = model.UsuarioFechaNacimiento;
                    _usuarioRepository.Create(usuario);
                    transaction.Commit();

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                    transaction.Rollback();
                    return BadRequest("error en la creacion");
                }
            }
            return Ok(1);
        }

        [HttpPost("Login")]
        public ActionResult Login(UsuarioLoginViewModel model)
        {
            Object token = new Object();

            var result = _usuarioRepository.Login(model.Email, model.Password);

            if(result == null)
            {
                return Unauthorized("Datos incorrectos");
            }

            token = CreacionTokenYClaims(result.UsuarioId, result.UsuarioNombre);

            return Ok(token);
        }

        private OkObjectResult CreacionTokenYClaims(string usuarioId, string usuarioNombre)
        {
            //Creacion de claims unico para el token
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, usuarioId.ToString()),
                new Claim(ClaimTypes.Name, usuarioNombre.ToString()),
            };

            //Generacion de Token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            var credenciales = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(120),
                SigningCredentials = credenciales,
            };

            var ManejadoreToken = new JwtSecurityTokenHandler();
            var token = ManejadoreToken.CreateToken(tokenDescriptor);

            return Ok(new
            {
                token = ManejadoreToken.WriteToken(token)
            });
        }

    }
}
