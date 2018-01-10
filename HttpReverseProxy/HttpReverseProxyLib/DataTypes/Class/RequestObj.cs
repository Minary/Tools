namespace HttpReverseProxyLib.DataTypes.Class
{
  using HttpReverseProxyLib.DataTypes.Class.Client;
  using HttpReverseProxyLib.DataTypes.Class.Server;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System;
  using System.Net.Sockets;
  using System.Text;


  public class RequestObj
  {

    #region PROPERTIES

    // Proxy server TCP connection
    public string SrcMac { get; set; }

    public string SrcIp { get; set; }

    public string SrcPort { get; set; }

    public TcpClient TcpClientConnection { get; set; }

    public ProxyProtocol ProxyProtocol { get; set; }


    // Client HTTP connection
    public ClientRequest ClientRequestObj { get; private set; }


    // Server HTTP connection
    public IOutgoingRequestClient ServerRequestHandler { get; set; }

    public ServerResponse ServerResponseObj { get; set; }

    public bool IsServerKeepAlive { get; set; }



    public DataTransmissionMode ProxyDataTransmissionModeS2C { get; set; }

    public DataTransmissionMode ProxyDataTransmissionModeC2S { get; set; }


    // ...
    public int Counter { get; set; }

    public string Id { get; set; }

    public string HttpLogData { get; set; }

    #endregion


    #region PUBLIC METHODS

    public RequestObj(string defaultHost, ProxyProtocol proxyProtocol)
    {
      // Client elements
      this.ClientRequestObj = new ClientRequest(defaultHost);

      // Server elements
      this.ServerResponseObj = new ServerResponse();


      // Request object elements
      this.InitRequestValues();
      this.ProxyProtocol = proxyProtocol;
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
      this.ClientRequestObj.ContentLength = 0;
      this.ClientRequestObj.ClientRequestData = string.Empty;
      this.ClientRequestObj.ClientRequestHeaders.Clear();

      this.ClientRequestObj.ContentTypeEncoding.ContentCharSet = "UTF-8";
      this.ClientRequestObj.ContentTypeEncoding.ContentCharsetEncoding = Encoding.UTF8;
      this.ClientRequestObj.ContentTypeEncoding.ContentType = "text/html";

      this.ClientRequestObj.IsClientKeepAlive = false;
      this.ClientRequestObj.Host = string.Empty;

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
