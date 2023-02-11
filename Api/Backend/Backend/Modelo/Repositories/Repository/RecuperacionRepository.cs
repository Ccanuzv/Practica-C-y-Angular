using Backend.Data;
using Backend.Modelo.Entity;
using Backend.Modelo.Repositories.IRepository;

namespace Backend.Modelo.Repositories.Repository
{
    public class RecuperacionRepository : Repository<RecuperacionContrasenia>, IRecuperacionRepository
    {
        private readonly PracticaDB _context;
        private readonly ILogger<RecuperacionContrasenia> _logger;

        public RecuperacionRepository(PracticaDB context, ILogger<RecuperacionContrasenia> logger) : base(context, logger)
        {
            _context = context;
            _logger = logger;
        }
    }
}
