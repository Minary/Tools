namespace HttpReverseProxy.Plugin.InjectFile.DataTypes
{

  public class InjectFileConfigRecord
  {

    #region PROPERTIES

    public string HostRegex { get; set; } = string.Empty;

    public string PathRegex { get; set; } = string.Empty;

    public string ReplacementResource { get; set; } = string.Empty;

    #endregion


    #region PUBLIC

    public InjectFileConfigRecord(string host, string path, string replacementResource)
    {
      this.HostRegex = host;
      this.PathRegex = path;
      this.ReplacementResource = replacementResource;
    }

    #endregion 

  }
}
