namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Enum;


  public class ClientRequestLine
  {

    #region PROPERTIES

    public string RequestLine { get; set; }

    public Newline NewlineType { get; set; }

    public string NewlineString { get; set; }

    public byte[] NewlineBytes { get; set; }

    public RequestMethod RequestMethod { get; set; }

    public string MethodString { get; set; }

    public string Path { get; set; }

    public string HttpVersion { get; set; }

    #endregion

  }
}
