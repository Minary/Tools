namespace HttpReverseProxyLib.DataTypes.Class.Server
{
  using HttpReverseProxyLib.DataTypes.Enum;


  public class ServerResponseStatusLine
  {

    #region PROPERTIES

    public string StatusLine { get; set; }

    public Newline NewlineType { get; set; }

    public string NewlineString { get; set; }

    public byte[] NewlineBytes { get; set; }

    public string HttpVersion { get; set; }

    public string StatusCode { get; set; }

    public string StatusDescription { get; set; }

    #endregion


    #region PUBLIC

    public ServerResponseStatusLine()
    {
      this.StatusLine = string.Empty;
      this.HttpVersion = string.Empty;
      this.StatusDescription = string.Empty;
    }

    public void Reset()
    {
      this.HttpVersion = string.Empty;
      this.StatusCode = string.Empty;
      this.StatusDescription = string.Empty;
    }

    #endregion

  }
}
