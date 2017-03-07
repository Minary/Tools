namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;

  public partial class ClientRequestSniffer
  {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="dataChunk"></param>
    public void OnServerDataTransfer(RequestObj requestObj, DataChunk dataChunk)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (dataChunk == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "ClientRequestSniffer.OnPostServerDataResponse(): ");
    }
  }
}
