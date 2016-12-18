namespace HttpReverseProxyLib.Interface
{
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using System.Collections;
  using System.Net.Sockets;

  public interface IOutgoingRequestClient
  {
    TcpClient ServerSocket { get; set; }

    // Server connection
    void OpenServerConnection(string host);

    void CloseServerConnection();

    // Server header transfer
    void ForwardRequestC2S(string requestMethod, string path, string httpVersion, byte[] newlineBytes);

    void ForwardHeadersC2S(Hashtable requestHeaders, byte[] clientNewlineBytes);

    ServerStatusLine ReadServerStatusLine(ServerStatusResponse serverStatusResponse);

    void ReadServerResponseHeaders(ServerResponseMetaData serverResponseMetaDataObj);

    // Client header transfer
    void ForwardStatusLineS2C(ServerStatusResponse serverStdatusResponseObj, byte[] serverNewlineBytes);

    void ForwardHeadersS2C(Hashtable serverResponseHeaders, byte[] clientNewlineBytes);

    // Client/Server data transfer
    void RelayDataC2S(bool mustBeProcessed, SniffedDataChunk dataChunk);

    void RelayDataS2C(bool mustBeProcessed);
  }
}
