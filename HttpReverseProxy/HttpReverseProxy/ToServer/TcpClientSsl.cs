namespace HttpReverseProxy.ToServer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using System;
  using System.IO;
  using System.Net.Security;
  using System.Net.Sockets;
  using System.Security.Cryptography.X509Certificates;
  using System.Text;


  public class TcpClientSsl : TcpClientBase
  {

    #region MEMBERS

    private const int TcpPortHttps = 443;
    private const int MaxBufferSize = 4096;

    private SslStream serverConnectionSslStream;

    #endregion


    #region PUBLIC

    public TcpClientSsl(RequestObj requestObj, MyBinaryReader clientStreamReader, BinaryWriter clientStreamWriter) :
      base(requestObj, TcpPortHttps)
    {
      base.clientStreamReader = clientStreamReader;
      base.clientStreamWriter = clientStreamWriter;
    }

    #endregion


    #region PRIVATE

    public bool ValidateCert(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
      return true; // Allow untrusted certificates.
    }

    #endregion


    #region INTERFACE overrides: IOutgoingRequestClient

    /// <summary>
    /// 
    /// </summary>
    /// <param name="host"></param>
    public override void OpenServerConnection(string host)
    {
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientSsl.OpenServerConnection()");

      if (string.IsNullOrEmpty(host))
      {
        throw new Exception("Host is invalid");
      }

      this.httpWebServerSocket = new TcpClient() { NoDelay = true };
      this.httpWebServerSocket.Connect(host, TcpPortHttps);

      this.serverConnectionSslStream = new SslStream(this.httpWebServerSocket.GetStream(), false, new RemoteCertificateValidationCallback(this.ValidateCert));
      this.serverConnectionSslStream.AuthenticateAsClient(host);

      this.webServerStreamReader = new MyBinaryReader(this.requestObj.ProxyProtocol, this.serverConnectionSslStream, 8192, Encoding.UTF8, this.requestObj.Id);
      this.webServerStreamWriter = new BinaryWriter(this.serverConnectionSslStream);
    }


    /// <summary>
    /// 
    /// </summary>
    public override void CloseServerConnection()
    {
      Logging.Instance.LogMessage(base.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "TcpClientSsl.CloseServerConnection()");

      if (this.serverConnectionSslStream != null)
      {
        this.serverConnectionSslStream.Close();
      }

      base.CloseServerConnection();
    }

    #endregion

  }
}
