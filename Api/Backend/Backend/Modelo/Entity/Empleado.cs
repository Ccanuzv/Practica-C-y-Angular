using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Backend.Modelo.Entity
{
    public class Empleado
    {
        [Key]
        public string EmpleadoId { get; set; }
        public string EmpleadoNombre { get; set; }
        public string EmpleadoDPI { get; set; }
        public int EmpleadoCantidadHijos { get; set; }
        public float EmpleadoSalario { get; set; }
        public float EmpleadoBonoDecreto { get; set; }
        public DateTime EmpleadoFechaCreacion { get; set; }
        [ForeignKey("Usuario")]
        public string EmpleadoUsuarioId { get; set; }
        public virtual Usuario Usuario { get; set; }

    }
}
