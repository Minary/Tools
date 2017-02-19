namespace HttpReverseProxy.Plugin.RequestRedirect
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;


  public partial class RequestRedirect
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("RequestRedirect", ProxyProtocol.Undefined, Loglevel.Debug, "RequestRedirect.OnUnload(): ");
    }
  }
}
