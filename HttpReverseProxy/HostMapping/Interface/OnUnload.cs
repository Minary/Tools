namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib;

  public partial class HostMapping
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("HostMapping", Logging.Level.DEBUG, "HostMapping.OnUnload():");
      
    }
  }
}
