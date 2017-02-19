namespace HttpReverseProxy.Plugin.Inject.DataTypes
{

  public class InjectConfigRecord
  {

    #region MEMBERS

    private string host;
    private string path;
    private string replacementResource;

    #endregion


    #region PROPERTIES

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }

    public string ReplacementResource { get { return this.replacementResource; } set { this.replacementResource = value; } }

    #endregion


    #region PUBLIC

    public InjectConfigRecord()
    {
      this.host = string.Empty;
      this.path = string.Empty;
      this.replacementResource = string.Empty;
    }

    public InjectConfigRecord(string host, string path, string replacementResource)
    {
      this.host = host;
      this.path = path;
      this.replacementResource = replacementResource;
    }

    #endregion 

  }
}
