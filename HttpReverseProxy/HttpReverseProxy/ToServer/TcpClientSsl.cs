namespace HttpReverseProxy.ToServer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
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

    public TcpClientSsl(RequestObj requestObj, NetworkStream clientStream) :
      base(requestObj, TcpPortHttps)
    {
      base.clientStreamReader = new MyBinaryReader(clientStream, 8192, Encoding.UTF8, base.requestObj.Id);
      base.clientStreamWriter = new BinaryWriter(clientStream);
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
    /// <param name="pHostName"></param>
    /// <param name="pPort"></param>
    /// <returns></returns>
    public override void OpenServerConnection(string host)
    {
      Logging.Instance.LogMessage(base.requestObj.Id, Logging.Level.DEBUG, "TcpClientSsl.OpenServerConnection()");

      if (string.IsNullOrEmpty(host))
      {
        throw new Exception("Host is invalid");
      }

      base.httpWebServerSocket = new TcpClient();
      base.httpWebServerSocket.NoDelay = true;
      base.httpWebServerSocket.Connect(host, TcpPortHttps);

      this.serverConnectionSslStream = new SslStream(base.httpWebServerSocket.GetStream(), false, new RemoteCertificateValidationCallback(this.ValidateCert));
      this.serverConnectionSslStream.AuthenticateAsClient(host);

      base.webServerStreamReader = new MyBinaryReader(this.serverConnectionSslStream, 8192, Encoding.UTF8, base.requestObj.Id);
      base.webServerStreamWriter = new BinaryWriter(this.serverConnectionSslStream);
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="pNetworkStream"></param>
    public override void CloseServerConnection()
    {
      Logging.Instance.LogMessage(base.requestObj.Id, Logging.Level.DEBUG, "TcpClientSsl.CloseServerConnection()");

      if (this.serverConnectionSslStream != null)
      {
        this.serverConnectionSslStream.Close();
      }

      base.CloseServerConnection();
    }

    #endregion

  }
}
