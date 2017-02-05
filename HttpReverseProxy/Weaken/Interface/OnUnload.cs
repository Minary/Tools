namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;


  public partial class Weaken
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("Weaken", ProxyProtocol.Undefined, Loglevel.Debug, "Weaken.OnUnload(): ");
    }
  }
}
