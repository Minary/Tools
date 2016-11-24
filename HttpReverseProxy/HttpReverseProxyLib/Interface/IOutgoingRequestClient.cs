namespace HttpReverseProxyLib.Interface
{
  using HttpReverseProxyLib.DataTypes;
  using System.Collections;
  using System.Net.Sockets;

  public interface IOutgoingRequestClient
  {
    TcpClient ServerSocket { get; set; }

    // Server connection
    void OpenServerConnection(string host);

    void CloseServerConnection();

    // Server header transfer
    void ForwardRequestC2S(string requestMethod, string path, string httpVersion);

    void ForwardHeadersC2S(Hashtable requestHeaders);

    void ReadServerStatusLine(ServerStatusResponse serverStatusResponse);

    void ReadServerResponseHeaders(ServerResponseMetaData serverResponseMetaDataObj);

    // Client header transfer
    void ForwardStatusLineS2C(ServerStatusResponse serverStdatusResponseObj);

    void ForwardHeadersS2C(Hashtable serverResponseHeaders);

    // Client/Server data transfer
    void RelayDataC2S(bool mustBeProcessed, SniffedDataChunk dataChunk);

    void RelayDataS2C(bool mustBeProcessed);
  }
}
