using Backend.Modelo.Entity;
using Microsoft.EntityFrameworkCore;

namespace Backend.Data
{
    public class PracticaDB: DbContext
    {

        public PracticaDB(DbContextOptions<PracticaDB> options) : base(options)
        {
        }

        public DbSet<Usuario> Usuarios => Set<Usuario>();
        public DbSet<Empleado> Empleados => Set<Empleado>();
        public DbSet<RecuperacionContrasenia> Recuperaciones => Set<RecuperacionContrasenia>();

    }
}
