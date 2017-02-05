namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;


  public partial class HostMapping
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("HostMapping", ProxyProtocol.Undefined, Loglevel.Debug, "HostMapping.OnUnload():");
    }
  }
}
