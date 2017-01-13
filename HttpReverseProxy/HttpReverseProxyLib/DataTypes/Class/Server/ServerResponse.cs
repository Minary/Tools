namespace HttpReverseProxyLib.DataTypes.Class.Server
{
  using HttpReverseProxyLib.DataTypes.Class;
  using System.Collections;
  using System.Collections.Generic;


  public class ServerResponse
  {

    #region MEMBERS

    private ServerResponseStatusLine statusLine;
    private DataContentTypeEncoding contentTypeEncoding;
    private int contentLen;
    private int noTransferredBytes;
    private Dictionary<string, List<string>> responseHeaders;

    #endregion


    #region PROPERTIES

    public DataContentTypeEncoding ContentTypeEncoding { get { return this.contentTypeEncoding; } set { this.contentTypeEncoding = value; } }

    public int ContentLength { get { return this.contentLen; } set { this.contentLen = value; } }
 
    public Dictionary<string, List<string>> ResponseHeaders { get { return this.responseHeaders; } set { this.responseHeaders = value; } }

    public ServerResponseStatusLine StatusLine { get { return this.statusLine; } set { this.statusLine = value; } }

    public int NoTransferredBytes { get { return this.noTransferredBytes; } set { this.noTransferredBytes = value; } }

    #endregion


    #region PUBLIC

    public ServerResponse()
    {
      this.contentTypeEncoding = new DataContentTypeEncoding();
      this.statusLine = new ServerResponseStatusLine();
      this.responseHeaders = new Dictionary<string, List<string>>();
      this.noTransferredBytes = 0;
    }

    #endregion

  }
}
