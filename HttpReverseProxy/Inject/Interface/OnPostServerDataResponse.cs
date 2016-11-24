namespace HttpReverseProxy.Plugin.Inject
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.Exceptions;

  public partial class Inject
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public void OnPostServerDataResponse(RequestObj requestObj, DataPacket dataPacket)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (dataPacket == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "Inject.OnPostServerDataResponse(): ");
    }
  }
}
