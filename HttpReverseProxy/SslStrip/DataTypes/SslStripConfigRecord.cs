namespace HttpReverseProxy.Plugin.SslStrip.DataTypes
{

  public class SslStripConfigRecord
  {

    #region MEMBERS

    private string host;
    private string contentType;

    #endregion


    #region PROPERTIES

    public string Host { get { return this.host; } set { this.host = value; } }

    public string ContentType { get { return this.contentType; } set { this.contentType = value; } }

    #endregion


    #region PUBLIC

    public SslStripConfigRecord()
    {
      this.host = string.Empty;
      this.contentType = string.Empty;
    }

    public SslStripConfigRecord(string host, string contentType)
    {
      this.host = host;
      this.contentType = contentType;
    }

    #endregion

  }
}
