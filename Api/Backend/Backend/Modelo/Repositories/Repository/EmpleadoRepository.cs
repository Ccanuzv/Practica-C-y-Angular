using Backend.Data;
using Backend.Modelo.Entity;
using Backend.Modelo.Repositories.IRepository;

namespace Backend.Modelo.Repositories.Repository
{
    public class EmpleadoRepository : Repository<Empleado>, IEmpleadoRepository
    {

        private readonly PracticaDB _context;
        private readonly ILogger<Empleado> _logger;

        public EmpleadoRepository(PracticaDB context, ILogger<Empleado> logger) : base(context, logger)
        {
            _context = context;
            _logger = logger;
        }
    }
}
