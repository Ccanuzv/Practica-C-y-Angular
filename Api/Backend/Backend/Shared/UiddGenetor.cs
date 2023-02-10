namespace Backend.Shared
{
    public class UiddGenetor
    {
        public static string uidd()
        {
            Guid myuuid = Guid.NewGuid();
            string myuuidString = myuuid.ToString();
            return myuuidString;
        }

    }
}
