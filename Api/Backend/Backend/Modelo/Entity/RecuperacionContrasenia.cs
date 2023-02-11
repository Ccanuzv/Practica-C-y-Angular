using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Backend.Modelo.Entity
{
    public class RecuperacionContrasenia
    {
        [Key]
        public string RecuperacionId { get; set; }
        public Boolean RecuperacionEstado { get; set; }
        public DateTime RecuperacionFechaCreacion { get; set; }
        [ForeignKey("Usuario")]
        public string RecuperacionUsuarioId { get; set; }
        public virtual Usuario Usuario { get; set; }
    }
}
