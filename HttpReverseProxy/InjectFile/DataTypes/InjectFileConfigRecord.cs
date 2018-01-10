namespace HttpReverseProxy.Plugin.InjectFile.DataTypes
{

  public class InjectFileConfigRecord
  {

    #region PROPERTIES

    public string Host { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    public string ReplacementResource { get; set; } = string.Empty;

    #endregion


    #region PUBLIC

    public InjectFileConfigRecord(string host, string path, string replacementResource)
    {
      this.Host = host;
      this.Path = path;
      this.ReplacementResource = replacementResource;
    }

    #endregion 

  }
}
