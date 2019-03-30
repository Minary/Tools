namespace HttpReverseProxy.Plugin.InjectFile.DataTypes
{
  using System.Text.RegularExpressions;


  public class InjectFileConfigRecord
  {

    #region PROPERTIES

    public string HostnameStr { get; set; } = string.Empty;

    public Regex HostnameRegex { get; set; } 

    public string PathStr { get; set; } = string.Empty;

    public Regex PathRegex { get; set; }

    public string ReplacementResource { get; set; } = string.Empty;

    #endregion


    #region PUBLIC

    public InjectFileConfigRecord(string host, string path, string replacementResource)
    {
      this.HostnameStr = host;
      this.PathStr = path;
      this.ReplacementResource = replacementResource;
    }

    #endregion 

  }
}
