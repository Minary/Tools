namespace HttpReverseProxy.Plugin.InjectCode.DataTypes
{
  using System.IO;


  public class InjectCodeConfigRecord
  {
  
    #region PROPERTIES

    public string HostRegex { get; set; } = string.Empty;

    public string PathRegex { get; set; } = string.Empty;

    public string InjectionCodeFile { get; set; } = string.Empty;

    public string InjectionCodeFileContent { get; set; } = string.Empty;

    public string Tag { get; set; } = string.Empty;

    public string TagRegex { get; set; } = string.Empty;

    public TagPosition Position { get; set; }

    #endregion


    #region PUBLIC

    public InjectCodeConfigRecord(string hostRegex, string pathRegex, string injectionCodeFile, string tag, TagPosition position)
    {
      this.HostRegex = hostRegex;
      this.PathRegex = pathRegex;
      this.InjectionCodeFile = injectionCodeFile;
      this.Tag = tag;
      this.Position = position;      
      this.TagRegex = $@"(<\s*{tag}[^>]*>)";
      this.InjectionCodeFileContent = File.ReadAllText(injectionCodeFile);
    }

    #endregion 

  }
}
