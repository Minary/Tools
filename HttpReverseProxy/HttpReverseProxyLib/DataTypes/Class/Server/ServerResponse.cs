namespace HttpReverseProxyLib.DataTypes.Class.Server
{
  using HttpReverseProxyLib.DataTypes.Class;
  using System.Collections.Generic;


  public class ServerResponse
  {

    #region PROPERTIES

    public DataContentTypeEncoding ContentTypeEncoding { get; set; } = new DataContentTypeEncoding();

    public int ContentLength { get; set; }

    public Dictionary<string, List<string>> ResponseHeaders { get; set; } = new Dictionary<string, List<string>>();

    public ServerResponseStatusLine StatusLine { get; set; } = new ServerResponseStatusLine();

    public int NoTransferredBytes { get; set; } = 0;

    #endregion

  }
}
