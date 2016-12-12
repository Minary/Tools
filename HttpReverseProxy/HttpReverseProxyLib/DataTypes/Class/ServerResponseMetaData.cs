namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Class;
  using System.Collections;


  public class ServerResponseMetaData
  {

    #region MEMBERS

    private DataContentTypeEncoding contentTypeEncoding;
    private int contentLen;
    private Hashtable responseHeaders;

    #endregion


    #region PROPERTIES

    public DataContentTypeEncoding ContentTypeEncoding { get { return this.contentTypeEncoding; } set { this.contentTypeEncoding = value; } }
    public int ContentLength { get { return this.contentLen; } set { this.contentLen = value; } }
    public Hashtable ResponseHeaders { get { return this.responseHeaders; } set { this.responseHeaders = value; } }

    #endregion


    #region PUBLIC

    public ServerResponseMetaData()
    {
      this.contentTypeEncoding = new DataContentTypeEncoding();
    }

    #endregion

  }
}
