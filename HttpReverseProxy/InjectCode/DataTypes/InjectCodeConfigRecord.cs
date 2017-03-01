namespace HttpReverseProxy.Plugin.InjectCode.DataTypes
{
  using System.IO;

  public class InjectCodeConfigRecord
  {

    #region MEMBERS

    private string host;
    private string path;
    private string injectionCodeFileContent;
    private string injectionCodeFile;
    private string tag;
    private string tagRegex;
    private TagPosition position;

    #endregion


    #region PROPERTIES

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }
    
    public string InjectionCodeFile { get { return this.injectionCodeFile; } set { this.injectionCodeFile = value; } }

    public string InjectionCodeFileContent { get { return this.injectionCodeFileContent; } set { this.injectionCodeFileContent = value; } }

    public string Tag { get { return this.tag; } set { this.tag = value; } }

    public string TagRegex { get { return this.tagRegex; } set { this.tagRegex = value; } }

    public TagPosition Position { get { return this.position; } set { this.position = value; } }

    #endregion


    #region PUBLIC

    public InjectCodeConfigRecord(string host, string path, string injectionCodeFile, string tag, TagPosition position)
    {
      this.host = host;
      this.path = path;
      this.injectionCodeFile = injectionCodeFile;
      this.tag = tag;
      this.position = position;
      
      this.tagRegex = string.Format(@"(<\s*{0}[^>]*>)", tag);
      this.injectionCodeFileContent = File.ReadAllText(injectionCodeFile);
    }

    #endregion 

  }
}
