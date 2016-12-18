namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Enum;


  public class ServerStatusLine
  {

    #region PROPERTIES

    public string StatusLine { get; set; }

    public Newline NewlineType { get; set; }

    public string NewlineString { get; set; }

    public byte[] NewlineBytes { get; set; }

    #endregion

  }
}
