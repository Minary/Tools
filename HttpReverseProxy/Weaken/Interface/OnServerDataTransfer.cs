namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;


  public partial class Weaken
  {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="dataPacket"></param>
    public void OnServerDataTransfer(RequestObj requestObj, DataChunk dataPacket)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (dataPacket == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "Weaken.OnPostServerDataResponse(): ");
    }
  }
}
