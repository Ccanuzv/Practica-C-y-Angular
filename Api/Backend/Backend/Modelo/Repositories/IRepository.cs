namespace Backend.Modelo.Repositories
{
    public interface IRepository<T> where T : class
    {
        IEnumerable<T> GetAll();
        int Create(T entity);
        bool Update(T entity);

    }
}
