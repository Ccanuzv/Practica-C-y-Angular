using Backend.Data;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Backend.Modelo.Repositories
{
    public class Repository<T> where T : class
    {
        private readonly PracticaDB _context;
        private readonly ILogger<T> _logger;

        public Repository(PracticaDB context, ILogger<T> logger)
        {
            _context = context;
            _logger = logger;

        }

        public int Create(T entity)
        {
            try
            {
                _context.Add(entity);

                return _context.SaveChanges();
            }
            catch (IOException e)
            {
                if (e.Source != null)
                    Console.WriteLine("IOException source: {0}", e.Source);
                throw;
            }
        }

        public IEnumerable<T> GetAll()
        {
            return _context.Set<T>();
        }

        public bool Update(T entity)
        {
            try
            {
                _context.Update(entity);
            }
            catch (IOException e)
            {
                if (e.Source != null)
                    Console.WriteLine("IOException source: {0}", e.Source);
                throw;
            }

            return _context.SaveChanges() > 0;
        }



    }
}
