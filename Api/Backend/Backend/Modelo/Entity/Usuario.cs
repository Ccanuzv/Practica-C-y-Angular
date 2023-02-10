using System.ComponentModel.DataAnnotations;

namespace Backend.Modelo.Entity
{
    public class Usuario
    {
        [Key]
        public string UsuarioId { get; set; }
        public string UsuarioNombre { get; set; }
        public string UsuarioEmail { get; set; }
        public string UsuarioPass { get; set; }
        public DateTime UsuarioFechaNacimiento { get; set; }


    }
}
