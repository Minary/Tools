namespace HttpReverseProxy.ToServer
{
  using HttpReverseProxyLib.DataTypes;
  using System.IO;
  using System.Net.Sockets;
  using System.Text;


  public class TcpClientPlainText : TcpClientBase
  {

    #region MEMBERS

    private const int TcpPortHttp = 80;
    private const int MaxBufferSize = 4096;

    #endregion


    #region PUBLIC

    public TcpClientPlainText(RequestObj requestObj, MyBinaryReader clientStreamReader, BinaryWriter clientStreamWriter) :
      base(requestObj, TcpPortHttp)
    {
      base.clientStreamReader = clientStreamReader;
      base.clientStreamWriter = clientStreamWriter;
    }

    #endregion

  }
}
