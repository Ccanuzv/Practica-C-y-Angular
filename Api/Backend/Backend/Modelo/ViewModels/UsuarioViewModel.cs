using System.ComponentModel.DataAnnotations;

namespace Backend.Modelo.ViewModels
{
    public class UsuarioCrearViewModel
    {
        [Required]
        public string Nombre { get; set; }

        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
        [Required]
        public DateTime UsuarioFechaNacimiento { get; set; }

    }

    public class UsuarioViewModel
    {
        public string Nombre { get; set; }
        public string Email { get; set; }

    }

    public class UsuarioLoginViewModel
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }

    }
    
}
