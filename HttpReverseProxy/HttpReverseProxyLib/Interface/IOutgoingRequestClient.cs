namespace HttpReverseProxyLib.Interface
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Class.Server;
  using System.Collections;
  using System.Net.Sockets;

  public interface IOutgoingRequestClient
  {
    TcpClient ServerSocket { get; set; }

    // Server connection
    void OpenServerConnection(string host);

    void CloseServerConnection();


    // Client header transfer
    void ForwardRequestC2S(string requestMethod, string path, string httpVersion, byte[] newlineBytes);

    void ForwardHeadersC2S(Hashtable requestHeaders, byte[] clientNewlineBytes);

    void ReadServerStatusLine(RequestObj requestObj);

    void ReadServerResponseHeaders(ServerResponse serverResponseMetaDataObj);


    // Server header transfer
    void ForwardStatusLineS2C(ServerResponseStatusLine serverResponseStatusLine);

    void ForwardHeadersS2C(Hashtable serverResponseHeaders, byte[] clientNewlineBytes);


    // Client/Server data transfer
    void RelayDataC2S(bool mustBeProcessed, SniffedDataChunk dataChunk);

    void RelayDataS2C(bool mustBeProcessed);
  }
}
