using Backend.Modelo.Entity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Backend.Modelo.ViewModels
{
    public class EmpleadoCrearViewModel
    {
        public string Nombre { get; set; }
        public string DPI { get; set; }
        public int CantidadHijos { get; set; }
        public float Salario { get; set; }
        public float BonoDecreto { get; set; }
    }

    public class EmpleadoViewModel
    {
        public string Id { get; set; }
        public string Nombre { get; set; }
        public string DPI { get; set; }
        public int CantidadHijos { get; set; }
        public float Salario { get; set; }
        public float BonoDecreto { get; set; }
        public DateTime FechaCreacion { get; set; }
        public string UsuarioId { get; set; }
        public UsuarioViewModel Usuario { get; set; }
        public float _igss;
        public float IGSS{
            get { return (float)(Salario*4.83/100); }
            set => _igss = value;
        }
        public float _irtra;
        public float IRTRA
        {
            get { return (float)(Salario * 1 / 100); }
            set => _irtra = value;
        }
        public float _bonoPaternidad;
        public float BonoPaternidad
        {
            get { return (float)(133*CantidadHijos); }
            set => _bonoPaternidad = value;
        }

        public float _salarioTotal;
        public float SalarioTotal
        {
            get { return (float)(Salario+BonoPaternidad+BonoDecreto); }
            set => _salarioTotal = value;
        }

        public float _salarioLiquido;
        public float SalarioLiquido
        {
            get { return (float)(SalarioTotal - IGSS - IRTRA); }
            set => _salarioLiquido = value;
        }


    }
}
