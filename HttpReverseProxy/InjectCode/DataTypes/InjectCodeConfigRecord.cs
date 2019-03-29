namespace HttpReverseProxy.Plugin.InjectCode.DataTypes
{
  using System.IO;
  using System.Text.RegularExpressions;


  public class InjectCodeConfigRecord
  {
  
    #region PROPERTIES

    public string HostnameStr { get; set; } = string.Empty;

    public Regex HostnameRegex { get; set; }

    public string PathStr { get; set; } = string.Empty;

    public Regex PathRegex { get; set; }

    public string InjectionCodeFile { get; set; } = string.Empty;

    public string InjectionCodeFileContent { get; set; } = string.Empty;

    public string Tag { get; set; } = string.Empty;

    public string TagRegex { get; set; } = string.Empty;

    public TagPosition Position { get; set; }

    #endregion


    #region PUBLIC

    public InjectCodeConfigRecord(string hostRegex, string pathRegex, string injectionCodeFile, string tag, TagPosition position)
    {
      this.HostnameStr = hostRegex;
      this.PathStr = pathRegex;
      this.InjectionCodeFile = injectionCodeFile;
      this.Tag = tag;
      this.Position = position;      
      this.TagRegex = $@"(<\s*{tag}[^>]*>)";
      this.InjectionCodeFileContent = File.ReadAllText(injectionCodeFile);
    }

    #endregion 

  }
}
