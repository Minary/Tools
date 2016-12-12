namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using System.Collections;
  using System.IO;


  public class ClientRequest
  {

    #region MEMBERS

    private string defaultHost;

    private RequestMethod requestMethod;
    private string methodString;
    private string host;
    private string path;
    private string httpVersion;
    private string scheme;
    private bool isClientKeepAlive;
    private DataContentTypeEncoding contentTypeEncoding;

    private IncomingClientRequest clientWebRequestHandler;
    private string clientRequestLine;
    private Hashtable clientRequestHeaders;
    private MyBinaryReader clientBinaryReader;
    private BinaryWriter clientBinaryWriter;

    private int clientRequestContentLength;
    private string clientRequestData;

    private byte[] serverNewLine;

    #endregion


    #region PROPERTIES

    public RequestMethod RequestMethod { get { return this.requestMethod; } set { this.requestMethod = value; } }

    public string MethodString { get { return this.methodString; } set { this.methodString = value; } }

    public string Host { get { return this.host; } set { this.host = value; } }

    public string Path { get { return this.path; } set { this.path = value; } }

    public string HttpVersion { get { return this.httpVersion; } set { this.httpVersion = value; } }

    public string Scheme { get { return this.scheme; } set { this.scheme = value; } }

    public bool IsClientKeepAlive { get { return this.isClientKeepAlive; } set { this.isClientKeepAlive = value; } }

    public DataContentTypeEncoding ContentTypeEncoding { get { return this.contentTypeEncoding; } set { this.contentTypeEncoding = value; } }

    public IncomingClientRequest ClientWebRequestHandler { get { return this.clientWebRequestHandler; } set { this.clientWebRequestHandler = value; } }

    public string ClientRequestLine { get { return this.clientRequestLine; } set { this.clientRequestLine = value; } }

    public Hashtable ClientRequestHeaders { get { return this.clientRequestHeaders; } set { this.clientRequestHeaders = value; } }

    public MyBinaryReader ClientBinaryReader { get { return this.clientBinaryReader; } set { this.clientBinaryReader = value; } }

    public BinaryWriter ClientBinaryWriter { get { return this.clientBinaryWriter; } set { this.clientBinaryWriter = value; } }

    public int ClientRequestContentLength { get { return this.clientRequestContentLength; } set { this.clientRequestContentLength = value; } }

    public string ClientRequestData { get { return this.clientRequestData; } set { this.clientRequestData = value; } }

    public byte[] ServerNewLine { get { return this.serverNewLine; } set { this.serverNewLine = value; } }

    #endregion


    #region PUBLIC

    public ClientRequest(string defaultHost)
    {
      this.defaultHost = defaultHost;

      this.clientRequestContentLength = 0;
      this.clientRequestHeaders = new Hashtable();
      this.contentTypeEncoding = new DataContentTypeEncoding();
      this.clientBinaryReader = null;
      this.clientBinaryWriter = null;

      this.methodString = string.Empty;
      this.scheme = "http";
      this.host = string.Empty;
      this.path = string.Empty;
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
        requestUrl = string.Format("{0}://{1}{2}", this.scheme, this.host, this.path);
      }
      else
      {
        requestUrl = string.Format("{0}://{1}{2}", this.scheme, this.defaultHost, this.path);
      }

      return requestUrl;
    }

    #endregion

  }
}
