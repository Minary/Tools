namespace HttpReverseProxyLib.DataTypes.Interface
{
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Class.Server;
  using System.Collections;
  using System.Collections.Generic;
  using System.Net.Sockets;

  public interface IOutgoingRequestClient
  {
    TcpClient ServerSocket { get; set; }

    // Server connection
    void OpenServerConnection(string host);

    void CloseServerConnection();


    // Client header transfer
    void ForwardRequestC2S(string requestMethod, string path, string httpVersion, byte[] newlineBytes);

    void ForwardHeadersC2S(Dictionary<string, List<string>> requestHeaders, byte[] clientNewlineBytes);

    void ReadServerStatusLine(RequestObj requestObj);

    void ReadServerResponseHeaders(ServerResponse serverResponseMetaDataObj);


    // Server header transfer
    void ForwardStatusLineS2C(ServerResponseStatusLine serverResponseStatusLine);

    void ForwardHeadersS2C(Dictionary<string, List<string>> serverResponseHeaders, byte[] clientNewlineBytes);


    // Client/Server data transfer
    int RelayDataC2S(bool mustBeProcessed, SniffedDataChunk dataChunk);

    int RelayDataS2C(bool mustBeProcessed);

  }
}
