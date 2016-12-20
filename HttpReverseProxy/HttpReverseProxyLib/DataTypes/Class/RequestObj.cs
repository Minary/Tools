namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Class.Client;
  using HttpReverseProxyLib.DataTypes.Class.Server;
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
    private ServerResponse serverResponseObj;
    private IOutgoingRequestClient serverRequestHandler;
    private bool isServerKeepAlive;

    private DataTransmissionMode proxyDataTransmissionModeS2C;
    private DataTransmissionMode proxyDataTransmissionModeC2S;

    // ...
    private int counter;
    private string id;
    private string httpLogData;
    

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
    public IOutgoingRequestClient ServerRequestHandler { get { return this.serverRequestHandler; } set { this.serverRequestHandler = value; } }

    public ServerResponse ServerResponseObj { get { return this.serverResponseObj; } set { this.serverResponseObj = value; } }

    public bool IsServerKeepAlive { get { return this.isServerKeepAlive; } set { this.isServerKeepAlive = value; } }






    public DataTransmissionMode ProxyDataTransmissionModeS2C { get { return this.proxyDataTransmissionModeS2C; } set { this.proxyDataTransmissionModeS2C = value; } }

    public DataTransmissionMode ProxyDataTransmissionModeC2S { get { return this.proxyDataTransmissionModeC2S; } set { this.proxyDataTransmissionModeC2S = value; } }



    // ...
    public int Counter { get { return this.counter; } set { this.counter = value; } }

    public string Id { get { return this.id; } set { this.id = value; } }

    public string HttpLogData { get { return this.httpLogData; } set { this.httpLogData = value; } }

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

      // Server elements
      this.ServerResponseObj = new ServerResponse();

      this.IsServerKeepAlive = false;
      this.HttpLogData = string.Empty;
      this.Counter = 0;
      this.ProxyDataTransmissionModeS2C = DataTransmissionMode.Undefined;

      // Determine request identifier
      this.Id = System.IO.Path.GetRandomFileName();
      try
      {
        this.Id = this.Id.Replace(".", string.Empty); // Remove period.
      }
      catch (Exception)
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

      this.ClientRequestObj.ContentTypeEncoding.ContentCharSet = "UTF-8";
      this.ClientRequestObj.ContentTypeEncoding.ContentCharsetEncoding = Encoding.UTF8;
      this.ClientRequestObj.ContentTypeEncoding.ContentType = "text/html";

      this.ClientRequestObj.IsClientKeepAlive = false;
      this.ClientRequestObj.Host = string.Empty;
      this.ClientRequestObj.Scheme = string.Empty;

      // Reset server settings
      this.ServerResponseObj.ContentLength = 0;
      this.ServerResponseObj.ContentTypeEncoding.ContentCharSet = "UTF-8";
      this.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding = Encoding.UTF8;
      this.ServerResponseObj.ContentTypeEncoding.ContentType = "text/html";
      this.ServerResponseObj.ResponseHeaders.Clear();
    }

    #endregion

  }
}
