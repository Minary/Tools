namespace HttpReverseProxy.Plugin.InjectCode.DataTypes
{
  using System.IO;


  public class InjectCodeConfigRecord
  {

    #region MEMBERS

    private string hostRegex;
    private string pathRegex;
    private string injectionCodeFileContent;
    private string injectionCodeFile;
    private string tag;
    private string tagRegex;
    private TagPosition position;

    #endregion


    #region PROPERTIES

    public string HostRegex { get { return this.hostRegex; } set { this.hostRegex = value; } }

    public string PathRegex { get { return this.pathRegex; } set { this.pathRegex = value; } }
    
    public string InjectionCodeFile { get { return this.injectionCodeFile; } set { this.injectionCodeFile = value; } }

    public string InjectionCodeFileContent { get { return this.injectionCodeFileContent; } set { this.injectionCodeFileContent = value; } }

    public string Tag { get { return this.tag; } set { this.tag = value; } }

    public string TagRegex { get { return this.tagRegex; } set { this.tagRegex = value; } }

    public TagPosition Position { get { return this.position; } set { this.position = value; } }

    #endregion


    #region PUBLIC

    public InjectCodeConfigRecord(string hostRegex, string pathRegex, string injectionCodeFile, string tag, TagPosition position)
    {
      this.hostRegex = hostRegex;
      this.pathRegex = pathRegex;
      this.injectionCodeFile = injectionCodeFile;
      this.tag = tag;
      this.position = position;
      
      this.tagRegex = string.Format(@"(<\s*{0}[^>]*>)", tag);
      this.injectionCodeFileContent = File.ReadAllText(injectionCodeFile);
    }

    #endregion 

  }
}
