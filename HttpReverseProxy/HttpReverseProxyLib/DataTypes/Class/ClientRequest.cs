namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using System.Collections;
  using System.IO;


  public class ClientRequest
  {

    #region MEMBERS

    private string defaultHost;
    private ClientRequestLine requestLine;
    private string host;
    private string scheme;
    private bool isClientKeepAlive;
    private DataContentTypeEncoding contentTypeEncoding;

    private IncomingClientRequest clientWebRequestHandler;
    private Hashtable clientRequestHeaders;
    private MyBinaryReader clientBinaryReader;
    private BinaryWriter clientBinaryWriter;

    private int clientRequestContentLength;
    private string clientRequestData;

    #endregion


    #region PROPERTIES

    public string Host { get { return this.host; } set { this.host = value; } }

    public ClientRequestLine RequestLine { get { return this.requestLine; } set { this.requestLine = value; } }

    public string Scheme { get { return this.scheme; } set { this.scheme = value; } }

    public bool IsClientKeepAlive { get { return this.isClientKeepAlive; } set { this.isClientKeepAlive = value; } }

    public DataContentTypeEncoding ContentTypeEncoding { get { return this.contentTypeEncoding; } set { this.contentTypeEncoding = value; } }

    public IncomingClientRequest ClientWebRequestHandler { get { return this.clientWebRequestHandler; } set { this.clientWebRequestHandler = value; } }

    public Hashtable ClientRequestHeaders { get { return this.clientRequestHeaders; } set { this.clientRequestHeaders = value; } }

    public MyBinaryReader ClientBinaryReader { get { return this.clientBinaryReader; } set { this.clientBinaryReader = value; } }

    public BinaryWriter ClientBinaryWriter { get { return this.clientBinaryWriter; } set { this.clientBinaryWriter = value; } }

    public int ClientRequestContentLength { get { return this.clientRequestContentLength; } set { this.clientRequestContentLength = value; } }

    public string ClientRequestData { get { return this.clientRequestData; } set { this.clientRequestData = value; } }
    
    #endregion


    #region PUBLIC
    
    public ClientRequest(string defaultHost)
    {
      this.requestLine = new ClientRequestLine();
      this.defaultHost = defaultHost;

      this.clientRequestContentLength = 0;
      this.clientRequestHeaders = new Hashtable();
      this.contentTypeEncoding = new DataContentTypeEncoding();
      this.clientBinaryReader = null;
      this.clientBinaryWriter = null;

      this.scheme = "http";
      this.host = string.Empty;
      this.isClientKeepAlive = false;
    }


    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public string GetRequestedUrl()
    {
      string requestUrl = string.Empty;

      if (!string.IsNullOrEmpty(this.host))
      {
        requestUrl = string.Format("{0}://{1}{2}", this.scheme, this.host, this.requestLine.Path);
      }
      else
      {
        requestUrl = string.Format("{0}://{1}{2}", this.scheme, this.defaultHost, this.requestLine.Path);
      }

      return requestUrl;
    }

    #endregion

  }
}
