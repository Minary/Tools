using HttpReverseProxyLib.DataTypes.Class;
using HttpReverseProxyLib.Exceptions;
using System.IO;
using System.Linq;
using System.Text;


namespace HttpReverseProxy.ToClient
{

  public class InstructionHandler
  {

    #region MEMBERS

    private TcpClientBase tcpClientConnection;

    #endregion 


    #region PUBLIC

    public InstructionHandler()
    {
      this.tcpClientConnection = new TcpClientBase();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="redirectUrl"></param>
    public void Redirect(RequestObj requestObj, InstructionParams parameters)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("Request object is invalid");
      }

      if (string.IsNullOrEmpty(parameters.Data))
      {
        throw new ProxyWarningException("Redirect URL is invalid");
      }

      string redirectData = Header.Redirect.GetHeader(parameters.Status, parameters.StatusDescription, parameters.Data, requestObj.ClientRequestObj.RequestLine.NewlineString);
      byte[] redirectDataByteArray = Encoding.UTF8.GetBytes(redirectData);
      this.tcpClientConnection.SendToClient(redirectDataByteArray, requestObj.ClientRequestObj.ClientBinaryWriter);
    }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="injectFilePath"></param>
    public void SendLocalFileToClient(RequestObj requestObj, InstructionParams parameters)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("Request object is invalid");
      }

      if (parameters == null)
      {
        throw new ProxyWarningException("Parameters object is invalid");
      }

      string injectFilePath = parameters.Data;
      if (string.IsNullOrEmpty(injectFilePath))
      {
        throw new ProxyWarningException("Inject file is invalid");
      }

      byte[] fileData = File.ReadAllBytes(injectFilePath);
      string redirectHeader = Header.SendFile.GetHeader(injectFilePath, fileData.Count(), requestObj.ClientRequestObj.RequestLine.NewlineString);
      byte[] redirectDataByteArray = Encoding.UTF8.GetBytes(redirectHeader);

      this.tcpClientConnection.SendToClient(redirectDataByteArray, requestObj.ClientRequestObj.ClientBinaryWriter);
      this.tcpClientConnection.SendToClient(fileData, requestObj.ClientRequestObj.ClientBinaryWriter);
    }

    #endregion

  }
}
