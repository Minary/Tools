namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{

  public class SslStripConfigRecord
  {

    #region PROPERTIES

    public string Host { get; set; } = string.Empty;

    public string ContentType { get; set; } = string.Empty;

    #endregion


    #region PUBLIC

    public SslStripConfigRecord(string host, string contentType)
    {
      this.Host = host;
      this.ContentType = contentType;
    }

    #endregion

  }
}
