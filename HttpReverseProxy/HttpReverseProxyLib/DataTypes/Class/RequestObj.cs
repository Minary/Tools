namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Interface;
  using System;
  using System.Collections;
  using System.Net.Sockets;
  using System.Text;


  public class RequestObj
  {

    #region MEMBERS

    // Client TCP connection
    private string srcMac;
    private string srcIp;
    private string srcPort;
    private TcpClient tcpClientConnection;

    // Client HTTP connection
    private ClientRequest clientRequestObj;

    // Server HTTP connection
    private bool isServerKeepAlive;
    private IOutgoingRequestClient serverRequestHandler;
    private ServerStatusResponse serverStatusResponseObj;
    private ServerResponseMetaData serverResponseMetaDataObj;

    private string serverResponseData;
    private DataTransmissionMode proxyDataTransmissionModeS2C;
    private DataTransmissionMode proxyDataTransmissionModeC2S;

    // ...
    private int counter;
    private string id;
    private string httpLogData;

    private StatusLine serverStatusLine;

    #endregion


    #region PROPERTIES

    // Proxy server TCP connection
    public string SrcMac { get { return this.srcMac; } set { this.srcMac = value; } }

    public string SrcIp { get { return this.srcIp; } set { this.srcIp = value; } }

    public string SrcPort { get { return this.srcPort; } set { this.srcPort = value; } }

    public TcpClient TcpClientConnection { get { return this.tcpClientConnection; } set { this.tcpClientConnection = value; } }


    // Client HTTP connection
    public ClientRequest ClientRequestObj { get { return this.clientRequestObj; } set { } }


    // Server HTTP connection
    public bool IsServerKeepAlive { get { return this.isServerKeepAlive; } set { this.isServerKeepAlive = value; } }

    public IOutgoingRequestClient ServerRequestHandler { get { return this.serverRequestHandler; } set { this.serverRequestHandler = value; } }

    public ServerStatusResponse ServerStatusResponseObj { get { return this.serverStatusResponseObj; } set { this.serverStatusResponseObj = value; } }

    public ServerResponseMetaData ServerResponseMetaDataObj { get { return this.serverResponseMetaDataObj; } set { this.serverResponseMetaDataObj = value; } }


    public string ServerResponseData { get { return this.serverResponseData; } set { this.serverResponseData = value; } }

    public DataTransmissionMode ProxyDataTransmissionModeS2C { get { return this.proxyDataTransmissionModeS2C; } set { this.proxyDataTransmissionModeS2C = value; } }

    public DataTransmissionMode ProxyDataTransmissionModeC2S { get { return this.proxyDataTransmissionModeC2S; } set { this.proxyDataTransmissionModeC2S = value; } }


    // ...
    public int Counter { get { return this.counter; } set { this.counter = value; } }

    public string Id { get { return this.id; } set { this.id = value; } }

    public string HttpLogData { get { return this.httpLogData; } set { this.httpLogData = value; } }


    public StatusLine ServerStatusLine { get { return this.serverStatusLine; } set { this.serverStatusLine = value; } }

    #endregion


    #region PUBLIC METHODS

    /// <summary>
    /// Initializes a new instance of the <see cref="RequestObj"/> class.
    ///
    /// </summary>
    /// <param name="defaultHost"></param>
    public RequestObj(string defaultHost)
    {
      // Client elements
      this.clientRequestObj = new ClientRequest(defaultHost);
      this.clientRequestObj.ContentTypeEncoding = new DataContentTypeEncoding();

      // Server elements
      this.IsServerKeepAlive = false;
      this.ServerStatusResponseObj = new ServerStatusResponse();
      this.ServerResponseMetaDataObj = new ServerResponseMetaData();
      this.ServerResponseMetaDataObj.ResponseHeaders = new Hashtable();

      this.HttpLogData = string.Empty;
      this.Counter = 0;
      this.ProxyDataTransmissionModeS2C = DataTransmissionMode.Undefined;

      // Determine request identifier
      this.Id = System.IO.Path.GetRandomFileName();
      try
      {
        this.Id = this.Id.Replace(".", string.Empty); // Remove period.
      }
      catch (Exception ex)
      {
        this.Id = DateTime.Now.ToString("MM/dd/yyyy hh:mm:ss.fff");
      }
    }


    /// <summary>
    ///
    /// </summary>
    public void InitRequestValues()
    {
      // Reset client settings
      this.ClientRequestObj.ClientRequestContentLength = 0;
      this.ClientRequestObj.ClientRequestData = string.Empty;
      this.clientRequestObj.ClientRequestHeaders.Clear();
      this.ClientRequestObj.ClientRequestLine = string.Empty;

      this.ClientRequestObj.ContentTypeEncoding.ContentCharSet = "UTF-8";
      this.ClientRequestObj.ContentTypeEncoding.ContentCharsetEncoding = Encoding.UTF8;
      this.ClientRequestObj.ContentTypeEncoding.ContentType = "text/html";

      this.ClientRequestObj.Host = string.Empty;
      this.ClientRequestObj.HttpVersion = string.Empty;
      this.ClientRequestObj.IsClientKeepAlive = false;
      this.ClientRequestObj.MethodString = string.Empty;
      this.ClientRequestObj.Path = string.Empty;
      this.ClientRequestObj.RequestMethod = RequestMethod.Undefined;
      this.ClientRequestObj.Scheme = string.Empty;

      // Reset server settings
      this.ServerResponseMetaDataObj.ContentLength = 0;
      this.ServerResponseMetaDataObj.ContentTypeEncoding.ContentCharSet = "UTF-8";
      this.ServerResponseMetaDataObj.ContentTypeEncoding.ContentCharsetEncoding = Encoding.UTF8;
      this.ServerResponseMetaDataObj.ContentTypeEncoding.ContentType = "text/html";
      this.ServerResponseMetaDataObj.ResponseHeaders.Clear();
    }

    #endregion

  }
}
