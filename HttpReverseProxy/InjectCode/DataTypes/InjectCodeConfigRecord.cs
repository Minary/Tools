namespace HttpReverseProxy.Plugin.InjectCode.DataTypes
{

  public class InjectCodeConfigRecord
  {

    #region MEMBERS

    private string host;
    private string path;
    private string injectionCodeFile;
    private string tag;
    private string position;

    #endregion


    #region PROPERTIES

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }

    public string InjectionCodeFile { get { return this.injectionCodeFile; } set { this.injectionCodeFile = value; } }

    public string Tag { get { return this.tag; } set { this.tag = value; } }

    public string Position { get { return this.position; } set { this.position = value; } }

    #endregion


    #region PUBLIC

    public InjectCodeConfigRecord()
    {
      this.host = string.Empty;
      this.path = string.Empty;
      this.injectionCodeFile = string.Empty;
      this.tag = string.Empty;
      this.position = string.Empty;
    }


    public InjectCodeConfigRecord(string host, string path, string injectionCodeFile, string tag, string position)
    {
      this.host = host;
      this.path = path;
      this.injectionCodeFile = injectionCodeFile;
      this.tag = tag;
      this.position = position;
    }

    #endregion 

  }
}
