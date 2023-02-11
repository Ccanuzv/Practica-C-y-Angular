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
using System.Net.Mail;
using System.Net;
using MimeKit;
using MimeKit.Text;
using System.Security.Cryptography;

namespace Backend.Controllers
{
    [Route("Core/[controller]")]
    [ApiController]
    public class UsuarioController : Controller
    {
        private readonly IUsuarioRepository _usuarioRepository;
        private readonly IRecuperacionRepository _recuperacionRepository;
        private readonly ILogger<UsuarioController> _logger;
        private readonly IConfiguration _config;
        private readonly PracticaDB _context;

        public UsuarioController(IUsuarioRepository usuarioRepository,
                                 ILogger<UsuarioController> logger,
                                 IConfiguration config,
                                 IRecuperacionRepository recuperacionRepository,
                                 PracticaDB context)
        {
            _usuarioRepository = usuarioRepository;
            _logger = logger;
            _config = config;
            _recuperacionRepository = recuperacionRepository;
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

        [HttpPost("Email")]
        public ActionResult PostEmail(string email)
        {
            var UsuarioEmail = _usuarioRepository.GetAll().Where(w => w.UsuarioEmail.Equals(email)).FirstOrDefault();

            if (UsuarioEmail != null)
            {
                RecuperacionContrasenia recu = new RecuperacionContrasenia();

                recu.RecuperacionId = UiddGenetor.uidd();
                recu.RecuperacionUsuarioId = UsuarioEmail.UsuarioId;
                recu.RecuperacionEstado = true;
                recu.RecuperacionFechaCreacion = DateTime.Now;
                _recuperacionRepository.Create(recu);

                //string url = "127.0.0.1:4200/recuperacion?id=" + recu.RecuperacionId;
                string url = "http://127.0.0.1:4200";

                var builder = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddUserSecrets<Conexion>().Build();
                string correo = builder.GetConnectionString("correo").ToString();
                string pass = builder.GetConnectionString("pass").ToString();

                SmtpClient cliente = new SmtpClient("smtp.gmail.com", 587)
                {
                    EnableSsl = true,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(correo, pass)
                };
                var email2 = new MailMessage(correo, UsuarioEmail.UsuarioEmail);
                email2.Subject = "Recuperación de Contraseña";
                //email2.Body = "Ingresa al siguiente para continuar con el proceso de recuperación de contraseña ";

                email2.Body = string.Format( "<html><body>" +
                                    "<p>Hi 👋,"+ UsuarioEmail.UsuarioNombre +"</p>" +
                                    "<p>Este correo te ayudará en el proceso recuperación de contraseña:</p>" +
                                    "<p>Has click aqui: <a href='{0}'>LINK</a> bye.</p>" +
                               "</body></html>", url);
                email2.IsBodyHtml = true;
                cliente.Send(email2);


            }

            return Ok(1);
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
