namespace Backend.Shared
{
    public class Constantes
    {
        public const int PAGE_SIZE = 10;
    }

    public class PagedResult<T>
    {
        public int Page { get; set; }

        public int PageSize { get; set; }

        public int PageCount { get; set; }

        public long Count { get; set; }

        public List<T> Data { get; private set; }

        public PagedResult() { }

        public PagedResult(IEnumerable<T> items, int pageNo, int pageSize, long totalRecordCount)
        {
            Data = new List<T>(items.ToList());
            Page = pageNo;
            PageSize = pageSize;
            Count = totalRecordCount;
            PageCount = totalRecordCount > 0 ? (int)Math.Ceiling(totalRecordCount / (double)pageSize) : 0;
        }

    }

}
